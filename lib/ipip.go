package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
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
	txBytes  uint64    // tx bytes observed at lastSeen, for activity detection
}

type connectIpipResponse struct {
	AssignedAddr string
}

// ipipIfnameMaxLen is the maximum visible length of a Linux interface name
// (IFNAMSIZ is 16 including the null terminator).
const ipipIfnameMaxLen = 15

// ipipIfname returns the Linux interface name used for the IPIP tunnel to
// the peer at peerIP.
//
// The name is "vp<srv.Index>-<offset>" where offset is the peer's distance
// from srv.WgCidr.Addr(). Using the full offset from the CIDR base (rather
// than e.g. the low 16 bits of peerIP) keeps the suffix globally unique
// across any allowed WgCidr width: for two distinct peers in the same
// server's CIDR, their offsets necessarily differ. The "vp<idx>-" prefix
// also gives us a stable wildcard (vp<idx>-+) for iptables.
//
// The function returns an error if the resulting name would exceed
// IFNAMSIZ. This never fires for production-sized CIDRs -- a /16 yields at
// most a 5-digit offset, well within budget alongside a 5-digit server
// index -- but it is a hard runtime guard against a CIDR wide enough
// (roughly /8 or wider, paired with a large server index) that the offset
// pushes the name past IFNAMSIZ, where kernel truncation could make two
// distinct peers collide on the same interface name.
func (srv *Server) ipipIfname(peerIP netip.Addr) (string, error) {
	base := srv.WgCidr.Addr().As4()
	p := peerIP.As4()
	baseInt := uint32(base[0])<<24 | uint32(base[1])<<16 |
		uint32(base[2])<<8 | uint32(base[3])
	peerInt := uint32(p[0])<<24 | uint32(p[1])<<16 |
		uint32(p[2])<<8 | uint32(p[3])
	offset := peerInt - baseInt
	name := fmt.Sprintf("vp%d-%d", srv.Index, offset)
	if len(name) > ipipIfnameMaxLen {
		return "", fmt.Errorf(
			"ipip ifname %q exceeds IFNAMSIZ (%d > %d); WgCidr is too wide for IPIP",
			name, len(name), ipipIfnameMaxLen)
	}
	return name, nil
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

	// Idempotent path: if we already have an IPIP tunnel for this client
	// IP and its kernel interface still exists, refresh lastSeen and
	// return the same assignment. If the interface vanished out-of-band
	// (manual `ip link del`, kernel reload, etc.) we cannot just refresh
	// lastSeen: a retrying client would keep the stale entry alive
	// forever, since removeIdleIpipPeers's freshness guard skips a peer
	// whose lastSeen was just bumped. Drop the stale entry and fall
	// through to fresh allocation.
	srv.ipipMu.Lock()
	existing, ok := srv.ipipPeers[clientIP]
	srv.ipipMu.Unlock()

	if ok {
		// Probe the interface without holding ipipMu, so the netlink
		// syscall doesn't block the idle loop or other requests. Only a
		// genuine "not found" counts as vanished: a transient lookup
		// failure must not tear down a working tunnel.
		_, lookupErr := netlink.LinkByName(existing.ifname)
		var notFound netlink.LinkNotFoundError
		vanished := errors.As(lookupErr, &notFound)
		if lookupErr != nil && !vanished {
			log.Printf("[%v] ipip iface %s lookup failed transiently (%v); reusing",
				srv.BindAddr, existing.ifname, lookupErr)
		}

		// Re-check identity under the lock: the entry may have been
		// reaped or replaced while ipipMu was released for the probe.
		srv.ipipMu.Lock()
		if current, stillOurs := srv.ipipPeers[clientIP]; !stillOurs || current != existing {
			// Entry changed under us; fall through to fresh allocation
			// (the race re-check below reconciles with the winner).
			srv.ipipMu.Unlock()
		} else if !vanished {
			current.lastSeen = time.Now()
			srv.ipipMu.Unlock()
			writeIpipResponse(w, fmt.Sprintf("%v/%d", existing.peerIP, srv.WgCidr.Bits()))
			return
		} else {
			delete(srv.ipipPeers, clientIP)
			srv.ipipMu.Unlock()
			log.Printf("[%v] ipip iface %s for %v vanished; rebuilding",
				srv.BindAddr, existing.ifname, clientIP)
			srv.removeIpipPeerFilter(existing.ifname, existing.peerIP)
			srv.ipAllocator.Free(existing.peerIP)
		}
	}

	peerIP := srv.ipAllocator.Allocate()
	if peerIP.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		return
	}

	ifname, err := srv.ipipIfname(peerIP)
	if err != nil {
		srv.ipAllocator.Free(peerIP)
		log.Printf("[%v] %v", srv.BindAddr, err)
		http.Error(w, "ipip ifname out of range", http.StatusInternalServerError)
		return
	}
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
		winner.lastSeen = time.Now()
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

	// Per-peer iptables filter: only accept forwarded traffic whose inner
	// source IP matches the peer we assigned this tunnel to, and drop
	// everything else arriving on this interface. A decapsulated IPIP
	// packet carries an attacker-controlled inner source, so this is what
	// stops a peer from injecting transit traffic claiming to be from a
	// different peer's inner IP. Inner packets that terminate on the host
	// itself go through INPUT instead, where ufw's default deny and
	// connectIpipHandler's check that the request did not originate from
	// inside srv.WgCidr together cover the control-plane concern.
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

		srv.removeIdleIpipPeers()
	}
}

// removeIdleIpipPeers prunes IPIP peers whose tunnel has seen no traffic for
// longer than PeerIdleTimeout. Activity is detected by polling the
// interface's rx_bytes and tx_bytes counters via netlink; counting both
// directions means a peer in the middle of a one-way transfer (e.g. a
// download with little return traffic) is not pruned mid-stream.
func (srv *Server) removeIdleIpipPeers() {
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
	type removal struct {
		snapshot
		vanished bool
	}
	var toRemove []removal
	for _, s := range snaps {
		link, err := netlink.LinkByName(s.ifname)
		if err != nil {
			// Only a genuine "not found" counts as vanished. A
			// transient lookup failure (kernel resource pressure, brief
			// netlink glitch, etc.) must NOT tear down an
			// actively-used tunnel, since vanished entries bypass the
			// lastSeen freshness guard below. Log and re-check next
			// poll instead. Matches the discrimination in
			// connectIpipHandler.
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				toRemove = append(toRemove, removal{snapshot: s, vanished: true})
			} else {
				log.Printf("[%v] ipip iface %s lookup failed transiently (%v); will retry",
					srv.BindAddr, s.ifname, err)
			}
			continue
		}
		stats := link.Attrs().Statistics
		var rx, tx uint64
		if stats != nil {
			rx = stats.RxBytes
			tx = stats.TxBytes
		}

		srv.ipipMu.Lock()
		if rx != s.peer.rxBytes || tx != s.peer.txBytes {
			s.peer.rxBytes = rx
			s.peer.txBytes = tx
			s.peer.lastSeen = now
		}
		idle := now.Sub(s.peer.lastSeen) > PeerIdleTimeout
		srv.ipipMu.Unlock()

		if idle {
			toRemove = append(toRemove, removal{snapshot: s})
		}
	}

	for _, r := range toRemove {
		srv.ipipMu.Lock()
		// Re-check inside the lock in case a fresh /connect-ipip from the
		// same client IP just replaced this entry.
		current, ok := srv.ipipPeers[r.clientIP]
		if !ok || current != r.peer {
			srv.ipipMu.Unlock()
			continue
		}
		// For idle-timeout removals, give a racing /connect-ipip that
		// bumped lastSeen the benefit of the doubt. For vanished
		// interfaces there's nothing to keep alive: the kernel state
		// is gone, so reap regardless of lastSeen.
		if !r.vanished && now.Sub(current.lastSeen) <= PeerIdleTimeout {
			srv.ipipMu.Unlock()
			continue
		}
		delete(srv.ipipPeers, r.clientIP)
		srv.ipipMu.Unlock()

		reason := "idle"
		if r.vanished {
			reason = "vanished"
		}
		log.Printf("[%v] removing %s ipip peer %v at %v",
			srv.BindAddr, reason, r.clientIP, r.peer.peerIP)
		srv.tearDownIpipLink(r.peer.ifname, r.peer.peerIP)
		srv.ipAllocator.Free(r.peer.peerIP)
	}
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
	if enabled {
		if err := srv.Ipt.AppendUnique("mangle", "FORWARD", out...); err != nil {
			return fmt.Errorf("append ipip outbound MSS rule: %v", err)
		}
		if err := srv.Ipt.AppendUnique("mangle", "FORWARD", in...); err != nil {
			return fmt.Errorf("append ipip inbound MSS rule: %v", err)
		}
		return nil
	}

	// Cleanup path: attempt both deletions independently so a failure on
	// the first doesn't leak the second (matches the WG MSS cleanup
	// pattern in CleanupIptables).
	if err := srv.Ipt.Delete("mangle", "FORWARD", out...); err != nil {
		log.Printf("failed to remove ipip outbound MSS rule: %v", err)
	}
	if err := srv.Ipt.Delete("mangle", "FORWARD", in...); err != nil {
		log.Printf("failed to remove ipip inbound MSS rule: %v", err)
	}
	return nil
}
