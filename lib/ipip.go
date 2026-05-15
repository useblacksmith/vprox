package lib

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/vishvananda/netlink"
)

// ipipPeer tracks server-side state for a single IPIP tunnel peer.
//
// One ipipPeer corresponds to exactly one Linux IPIP interface created on the
// server, with the peer's HTTPS source address as the remote tunnel endpoint
// and an inner IP allocated from srv.WgCidr.
type ipipPeer struct {
	clientIP netip.Addr // outer (HTTPS) source address of the client
	peerIP   netip.Addr // inner address allocated from srv.WgCidr
	ifname   string     // Linux interface name (e.g. vp0-1)

	lastSeen time.Time // last time we observed activity from this peer
	rxBytes  uint64    // rx bytes observed at lastSeen, for activity detection
}

type connectIpipResponse struct {
	AssignedAddr string
}

// ipipIfname returns the Linux interface name used for the IPIP tunnel to the
// peer at peerIP.
//
// The name is "vp<srv.Index>-<host>" where host is the low 16 bits of peerIP.
// This stays within IFNAMSIZ (15 visible chars) for all valid server indices
// and host portions of the WgCidr, and makes it possible to install one
// iptables wildcard rule per server (vp<srv.Index>-+) covering every IPIP
// peer attached to that server.
func (srv *Server) ipipIfname(peerIP netip.Addr) string {
	b := peerIP.As4()
	host := uint16(b[2])<<8 | uint16(b[3])
	return fmt.Sprintf("vp%d-%d", srv.Index, host)
}

// ipipIfaceWildcard returns the iptables-style wildcard that matches every
// IPIP interface created for this server.
func (srv *Server) ipipIfaceWildcard() string {
	return fmt.Sprintf("vp%d-+", srv.Index)
}

// connectIpipHandler handles POST /connect-ipip.
//
// It authenticates the request with the shared Bearer password (matching the
// existing /connect handler), allocates an inner IP from srv.ipAllocator,
// creates a Linux IPIP tunnel whose remote is the HTTPS source address of the
// request, installs a host route so that return traffic destined for the
// inner IP exits via that tunnel, and returns the assigned inner address.
//
// Repeated calls from the same client IP are idempotent: the existing peer
// is reused and its lastSeen timestamp refreshed.
func (srv *Server) connectIpipHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid remote address", http.StatusBadRequest)
		return
	}
	clientIP, err := netip.ParseAddr(host)
	if err != nil {
		http.Error(w, "invalid remote address", http.StatusBadRequest)
		return
	}
	if !clientIP.Is4() {
		http.Error(w, "ipv4 client address required", http.StatusBadRequest)
		return
	}

	// Idempotent path: if we already have an IPIP tunnel for this client IP,
	// refresh its lastSeen and return the same assignment.
	srv.ipipMu.Lock()
	if existing, ok := srv.ipipPeers[clientIP]; ok {
		existing.lastSeen = time.Now()
		assigned := fmt.Sprintf("%v/%d", existing.peerIP, srv.WgCidr.Bits())
		srv.ipipMu.Unlock()
		writeIpipResponse(w, assigned)
		return
	}
	srv.ipipMu.Unlock()

	peerIP := srv.ipAllocator.Allocate()
	if peerIP.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		return
	}

	ifname := srv.ipipIfname(peerIP)
	if err := srv.createIpipLink(ifname, clientIP, peerIP); err != nil {
		srv.ipAllocator.Free(peerIP)
		log.Printf("[%v] failed to create IPIP tunnel for %v: %v",
			srv.BindAddr, clientIP, err)
		http.Error(w, "failed to create IPIP tunnel", http.StatusInternalServerError)
		return
	}

	peer := &ipipPeer{
		clientIP: clientIP,
		peerIP:   peerIP,
		ifname:   ifname,
		lastSeen: time.Now(),
	}

	// Another request from the same client IP could have raced us. If so,
	// drop the one we just built and reuse the winner so we don't leak an
	// allocation or an interface.
	srv.ipipMu.Lock()
	if winner, ok := srv.ipipPeers[clientIP]; ok {
		srv.ipipMu.Unlock()
		srv.tearDownIpipLink(ifname, peerIP)
		srv.ipAllocator.Free(peerIP)
		writeIpipResponse(w, fmt.Sprintf("%v/%d", winner.peerIP, srv.WgCidr.Bits()))
		return
	}
	srv.ipipPeers[clientIP] = peer
	srv.ipipMu.Unlock()

	log.Printf("[%v] new ipip peer %v at %v (iface %s)",
		srv.BindAddr, clientIP, peerIP, ifname)

	writeIpipResponse(w, fmt.Sprintf("%v/%d", peerIP, srv.WgCidr.Bits()))
}

func writeIpipResponse(w http.ResponseWriter, assigned string) {
	resp := &connectIpipResponse{AssignedAddr: assigned}
	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBuf)
}

// createIpipLink creates the Linux IPIP interface and installs a host route
// pointing peerIP at it so return traffic finds the right tunnel.
//
// We intentionally do NOT add an IP address to the IPIP interface: the
// equivalent assignment in the WireGuard path puts srv.WgCidr.Addr() on the
// WireGuard interface, and adding the same local address to a second
// interface would either be rejected or break routing. A more-specific /32
// route per peer is enough to deliver decapsulated return traffic to the
// correct tunnel, and the MASQUERADE rule already in place on srv.BindIface
// handles outbound NAT.
func (srv *Server) createIpipLink(ifname string, remote, peerIP netip.Addr) error {
	link := &netlink.Iptun{
		LinkAttrs: netlink.LinkAttrs{Name: ifname},
		Local:     addrToIp(srv.BindAddr),
		Remote:    addrToIp(remote),
	}
	// Best-effort cleanup of any stale interface with the same name.
	_ = netlink.LinkDel(link)

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("add ipip link: %v", err)
	}

	// netlink.LinkAdd does not populate the struct's Index field, so look up
	// the link by name to get the kernel-assigned attributes (including the
	// real ifindex) before we install routes that depend on it.
	resolved, err := netlink.LinkByName(ifname)
	if err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("resolve ipip link %s: %v", ifname, err)
	}

	if err := netlink.LinkSetUp(resolved); err != nil {
		_ = netlink.LinkDel(resolved)
		return fmt.Errorf("bring up ipip link: %v", err)
	}

	// Pin the peer's inner IP to this tunnel so decapsulated return packets
	// go back out the right interface (a /32 wins over the /16 connected
	// route on the WireGuard interface).
	dst := prefixToIPNet(netip.PrefixFrom(peerIP, 32))
	route := &netlink.Route{
		LinkIndex: resolved.Attrs().Index,
		Dst:       &dst,
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(route); err != nil {
		_ = netlink.LinkDel(resolved)
		return fmt.Errorf("add host route for %v: %v", peerIP, err)
	}

	// Strict reverse-path filtering: the kernel drops decapsulated packets
	// whose inner source IP wouldn't route back through the same interface
	// they arrived on. Combined with the per-peer /32 route installed
	// above, this means an attacker who can send IPIP packets to us as
	// some registered client's outer IP still can't inject inner traffic
	// claiming to be from a different peer's inner IP.
	//
	// Linux uses max(conf.all.rp_filter, conf.<iface>.rp_filter), so
	// setting it to 1 here is enough regardless of the global default.
	// Best-effort: log and continue if the sysctl is missing.
	if err := setRpFilter(ifname, 1); err != nil {
		log.Printf("[%v] failed to enable rp_filter on %s: %v",
			srv.BindAddr, ifname, err)
	}

	// Per-peer iptables filter: only accept forwarded traffic whose inner
	// source IP matches the peer we assigned this tunnel to, and drop
	// everything else arriving on this interface. This is defence in depth
	// alongside rp_filter; it's enforced independently of the routing
	// table and is more obvious at audit time.
	if err := srv.addIpipPeerFilter(ifname, peerIP); err != nil {
		_ = netlink.LinkDel(resolved)
		return fmt.Errorf("install ipip peer filter: %v", err)
	}

	return nil
}

// tearDownIpipLink removes the per-peer iptables filter and the IPIP
// interface. The interface deletion is what carries the kernel state;
// removing the iptables rules first keeps them from referencing a vanished
// interface for the brief window before they're cleaned up.
func (srv *Server) tearDownIpipLink(ifname string, peerIP netip.Addr) {
	srv.removeIpipPeerFilter(ifname, peerIP)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		// Already gone; nothing to do.
		return
	}
	if err := netlink.LinkDel(link); err != nil {
		log.Printf("[%v] failed to delete ipip link %s: %v",
			srv.BindAddr, ifname, err)
	}
}

// setRpFilter writes the per-interface rp_filter sysctl. The /proc entry
// exists as soon as the interface is created.
func setRpFilter(ifname string, val int) error {
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifname)
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", val)), 0644)
}

// ipipPeerAcceptRule is the iptables rule that permits forwarded traffic
// arriving on this peer's IPIP interface with the expected inner source IP.
func ipipPeerAcceptRule(ifname string, peerIP netip.Addr) []string {
	return []string{
		"-i", ifname,
		"-s", fmt.Sprintf("%v/32", peerIP),
		"-j", "ACCEPT",
		"-m", "comment", "--comment",
		fmt.Sprintf("vprox ipip accept peer %v on %s", peerIP, ifname),
	}
}

// ipipPeerDropRule is the iptables rule that drops anything else arriving
// on this peer's IPIP interface (i.e. inner source spoofing).
func ipipPeerDropRule(ifname string) []string {
	return []string{
		"-i", ifname,
		"-j", "DROP",
		"-m", "comment", "--comment",
		fmt.Sprintf("vprox ipip drop spoofed on %s", ifname),
	}
}

func (srv *Server) addIpipPeerFilter(ifname string, peerIP netip.Addr) error {
	accept := ipipPeerAcceptRule(ifname, peerIP)
	if err := srv.Ipt.AppendUnique("filter", "FORWARD", accept...); err != nil {
		return fmt.Errorf("add ipip accept rule: %v", err)
	}
	drop := ipipPeerDropRule(ifname)
	if err := srv.Ipt.AppendUnique("filter", "FORWARD", drop...); err != nil {
		_ = srv.Ipt.Delete("filter", "FORWARD", accept...)
		return fmt.Errorf("add ipip drop rule: %v", err)
	}
	return nil
}

func (srv *Server) removeIpipPeerFilter(ifname string, peerIP netip.Addr) {
	// The interface is about to be deleted (or already is), so removal
	// order doesn't matter for security; either rule alone matches
	// nothing once the interface is gone. Use DeleteIfExists so a
	// partially-installed filter (e.g. failed mid-add) cleans up
	// without a noisy "rule does not exist" error.
	if err := srv.Ipt.DeleteIfExists("filter", "FORWARD", ipipPeerDropRule(ifname)...); err != nil {
		log.Printf("[%v] failed to remove ipip drop rule for %s: %v",
			srv.BindAddr, ifname, err)
	}
	if err := srv.Ipt.DeleteIfExists("filter", "FORWARD", ipipPeerAcceptRule(ifname, peerIP)...); err != nil {
		log.Printf("[%v] failed to remove ipip accept rule for %s: %v",
			srv.BindAddr, ifname, err)
	}
}

func (srv *Server) removeIdleIpipPeersLoop() {
	for {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		if err := srv.removeIdleIpipPeers(); err != nil {
			log.Printf("error removing idle ipip peers: %v", err)
		}
	}
}

// removeIdleIpipPeers prunes IPIP peers whose tunnel has seen no inbound
// traffic for longer than PeerIdleTimeout. Activity is detected by polling
// the interface's rx_bytes counter via netlink.
func (srv *Server) removeIdleIpipPeers() error {
	srv.ipipMu.Lock()
	type snapshot struct {
		clientIP netip.Addr
		ifname   string
		peer     *ipipPeer
	}
	snaps := make([]snapshot, 0, len(srv.ipipPeers))
	for clientIP, peer := range srv.ipipPeers {
		snaps = append(snaps, snapshot{clientIP: clientIP, ifname: peer.ifname, peer: peer})
	}
	srv.ipipMu.Unlock()

	now := time.Now()
	var toRemove []snapshot
	for _, s := range snaps {
		link, err := netlink.LinkByName(s.ifname)
		if err != nil {
			// The interface vanished out from under us. Treat as removable.
			toRemove = append(toRemove, s)
			continue
		}
		stats := link.Attrs().Statistics
		var rx uint64
		if stats != nil {
			rx = stats.RxBytes
		}

		srv.ipipMu.Lock()
		if rx != s.peer.rxBytes {
			s.peer.rxBytes = rx
			s.peer.lastSeen = now
		}
		idle := now.Sub(s.peer.lastSeen) > PeerIdleTimeout
		srv.ipipMu.Unlock()

		if idle {
			toRemove = append(toRemove, s)
		}
	}

	for _, s := range toRemove {
		srv.ipipMu.Lock()
		// Re-check inside the lock in case a fresh /connect-ipip from the
		// same client IP just bumped lastSeen.
		current, ok := srv.ipipPeers[s.clientIP]
		if !ok || current != s.peer {
			srv.ipipMu.Unlock()
			continue
		}
		if now.Sub(current.lastSeen) <= PeerIdleTimeout {
			srv.ipipMu.Unlock()
			continue
		}
		delete(srv.ipipPeers, s.clientIP)
		srv.ipipMu.Unlock()

		log.Printf("[%v] removing idle ipip peer %v at %v",
			srv.BindAddr, s.clientIP, s.peer.peerIP)
		srv.tearDownIpipLink(s.peer.ifname, s.peer.peerIP)
		srv.ipAllocator.Free(s.peer.peerIP)
	}
	return nil
}

// CleanupIpip tears down every IPIP interface this server created. It is
// safe to call multiple times.
func (srv *Server) CleanupIpip() {
	srv.ipipMu.Lock()
	peers := make([]*ipipPeer, 0, len(srv.ipipPeers))
	for _, p := range srv.ipipPeers {
		peers = append(peers, p)
	}
	srv.ipipPeers = make(map[netip.Addr]*ipipPeer)
	srv.ipipMu.Unlock()

	for _, p := range peers {
		srv.tearDownIpipLink(p.ifname, p.peerIP)
		srv.ipAllocator.Free(p.peerIP)
	}
}

// iptablesIpipMssRules adds or removes TCP MSS clamping for the IPIP
// interfaces (inbound and outbound) so traffic fits the tunnel MTU.
func (srv *Server) iptablesIpipMssRules(enabled bool) error {
	out := []string{
		"-o", srv.ipipIfaceWildcard(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment", "--comment",
		fmt.Sprintf("vprox ipip TCP MSS outbound rule for %s", srv.Ifname()),
	}
	in := []string{
		"-i", srv.ipipIfaceWildcard(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment", "--comment",
		fmt.Sprintf("vprox ipip TCP MSS inbound rule for %s", srv.Ifname()),
	}
	apply := srv.Ipt.AppendUnique
	op := "append"
	if !enabled {
		apply = srv.Ipt.Delete
		op = "delete"
	}
	if err := apply("mangle", "FORWARD", out...); err != nil {
		return fmt.Errorf("%s ipip outbound MSS rule: %v", op, err)
	}
	if err := apply("mangle", "FORWARD", in...); err != nil {
		return fmt.Errorf("%s ipip inbound MSS rule: %v", op, err)
	}
	return nil
}
