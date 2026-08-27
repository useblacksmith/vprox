package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
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

// ipipKernelOpWarnAfter is how long createIpipLink / tearDownIpipLink may
// block on netlink or xtables before we log. A hang here holds ipipMu, so
// every /connect-ipip waits; the user-visible signal is VM static-IP setup
// failures. The log is so those alerts are diagnosable.
const ipipKernelOpWarnAfter = 5 * time.Second

// watchIpipKernelOp logs if a kernel/iptables op is still running after
// ipipKernelOpWarnAfter, and again when it finally returns if it was slow.
// Call as `defer srv.watchIpipKernelOp("create vp0-1")()`.
func (srv *Server) watchIpipKernelOp(op string) func() {
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTimer(ipipKernelOpWarnAfter)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
			log.Printf("[%v] ipip %s still in progress after %s (netlink/xtables?)",
				srv.BindAddr, op, time.Since(start).Round(time.Millisecond))
		}
	}()
	return func() {
		close(done)
		if d := time.Since(start); d >= ipipKernelOpWarnAfter {
			log.Printf("[%v] ipip %s finished after %s",
				srv.BindAddr, op, d.Round(time.Millisecond))
		}
	}
}

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

// ipipPeerFromIfname is the inverse of ipipIfname: it recovers the peer's
// inner IP from a "vp<srv.Index>-<offset>" interface name. The startup sweep
// uses it to remove the per-peer iptables rules of tunnels left over from a
// previous process. Returns false if the name does not belong to this
// server's IPIP interfaces.
func (srv *Server) ipipPeerFromIfname(ifname string) (netip.Addr, bool) {
	suffix, found := strings.CutPrefix(ifname, fmt.Sprintf("vp%d-", srv.Index))
	if !found {
		return netip.Addr{}, false
	}
	offset, err := strconv.ParseUint(suffix, 10, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	base := srv.WgCidr.Addr().As4()
	baseInt := uint32(base[0])<<24 | uint32(base[1])<<16 |
		uint32(base[2])<<8 | uint32(base[3])
	peerInt := baseInt + uint32(offset)
	return netip.AddrFrom4([4]byte{
		byte(peerInt >> 24), byte(peerInt >> 16),
		byte(peerInt >> 8), byte(peerInt),
	}), true
}

// SweepStaleIpip removes IPIP interfaces (and their per-peer iptables rules)
// left over from a previous process. CleanupIpip only runs on a clean
// shutdown; after a crash or SIGKILL the interfaces survive while the new
// process starts with an empty allocator, so a leftover /32 host route could
// blackhole an IP the allocator later hands to a new WireGuard or IPIP peer.
// There is no adopt-on-restart path for IPIP (unlike WireGuard), so any
// surviving vp<srv.Index>-* tunnel is stale by definition.
//
// Sweep runs once at startup, before ListenForHttps, so there are no
// concurrent /connect-ipip handlers. It does not take ipipMu: it never
// touches ipipPeers (the map is empty) and holding the lock across a
// LinkList plus every leftover LinkDel would only delay listen.
func (srv *Server) SweepStaleIpip() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links for ipip sweep: %v", err)
	}
	for _, link := range links {
		ifname := link.Attrs().Name
		peerIP, ok := srv.ipipPeerFromIfname(ifname)
		if !ok {
			continue
		}
		if _, isIptun := link.(*netlink.Iptun); !isIptun {
			continue
		}
		log.Printf("[%v] sweeping stale ipip tunnel %s (peer %v)",
			srv.BindAddr, ifname, peerIP)
		srv.tearDownIpipLink(ifname, peerIP)
	}
	return nil
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

	assigned, errMsg, errStatus := srv.lookupOrCreateIpip(clientIP)
	if errMsg != "" {
		http.Error(w, errMsg, errStatus)
		return
	}
	writeIpipResponse(w, assigned)
}

// lookupOrCreateIpip returns the inner address for clientIP, creating the
// kernel tunnel if needed. It holds ipipMu for the whole lookup/create so
// the peer map and the kernel (local, remote) pair stay in lockstep. The
// HTTP response is written by the caller after this returns.
func (srv *Server) lookupOrCreateIpip(clientIP netip.Addr) (assigned, errMsg string, errStatus int) {
	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	if srv.ipipClosed {
		return "", "server shutting down", http.StatusServiceUnavailable
	}

	if existing, ok := srv.ipipPeers[clientIP]; ok {
		// Only a genuine "not found" counts as vanished. A transient
		// lookup failure must not tear down a working tunnel.
		_, lookupErr := netlink.LinkByName(existing.ifname)
		var notFound netlink.LinkNotFoundError
		vanished := errors.As(lookupErr, &notFound)
		if lookupErr != nil && !vanished {
			log.Printf("[%v] ipip iface %s lookup failed transiently (%v); reusing",
				srv.BindAddr, existing.ifname, lookupErr)
		}
		if !vanished {
			existing.lastSeen = time.Now()
			return fmt.Sprintf("%v/%d", existing.peerIP, srv.WgCidr.Bits()), "", 0
		}
		log.Printf("[%v] ipip iface %s for %v vanished; rebuilding",
			srv.BindAddr, existing.ifname, clientIP)
		delete(srv.ipipPeers, clientIP)
		srv.dropIpipPeerLocked(existing)
	}

	return srv.createIpipPeerLocked(clientIP)
}

// createIpipPeerLocked allocates an inner IP, creates the IPIP tunnel, and
// registers the peer. Caller must hold ipipMu. On success it returns the
// assigned inner address in CIDR notation; on failure a non-empty errMsg
// and HTTP status.
func (srv *Server) createIpipPeerLocked(clientIP netip.Addr) (assigned, errMsg string, errStatus int) {
	if winner, ok := srv.ipipPeers[clientIP]; ok {
		winner.lastSeen = time.Now()
		return fmt.Sprintf("%v/%d", winner.peerIP, srv.WgCidr.Bits()), "", 0
	}
	if srv.ipipClosed {
		return "", "server shutting down", http.StatusServiceUnavailable
	}

	peerIP := srv.ipAllocator.Allocate()
	if peerIP.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		return "", "no more IP addresses available", http.StatusServiceUnavailable
	}

	ifname, err := srv.ipipIfname(peerIP)
	if err != nil {
		srv.ipAllocator.Free(peerIP)
		log.Printf("[%v] %v", srv.BindAddr, err)
		return "", "ipip ifname out of range", http.StatusInternalServerError
	}
	if err := srv.createIpipLink(ifname, clientIP, peerIP); err != nil {
		srv.ipAllocator.Free(peerIP)
		log.Printf("[%v] failed to create IPIP tunnel for %v: %v",
			srv.BindAddr, clientIP, err)
		return "", "failed to create IPIP tunnel", http.StatusInternalServerError
	}

	srv.ipipPeers[clientIP] = &ipipPeer{
		clientIP: clientIP,
		peerIP:   peerIP,
		ifname:   ifname,
		lastSeen: time.Now(),
	}

	log.Printf("[%v] new ipip peer %v at %v (iface %s)",
		srv.BindAddr, clientIP, peerIP, ifname)

	return fmt.Sprintf("%v/%d", peerIP, srv.WgCidr.Bits()), "", 0
}

// dropIpipPeerLocked removes the kernel objects and frees the inner IP for
// p. Caller must hold ipipMu and must already have deleted p from
// ipipPeers (or be replacing the whole map).
func (srv *Server) dropIpipPeerLocked(p *ipipPeer) {
	srv.tearDownIpipLink(p.ifname, p.peerIP)
	srv.ipAllocator.Free(p.peerIP)
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
	defer srv.watchIpipKernelOp("create " + ifname)()

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
	defer srv.watchIpipKernelOp("teardown " + ifname)()

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
//
// Stats probes run without ipipMu so a full scan does not stall handshakes.
// Map updates and kernel teardown run under the lock so we never delete the
// map entry while leaving vp0-N in the kernel (or the reverse).
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
	for _, s := range snaps {
		link, err := netlink.LinkByName(s.ifname)
		var notFound netlink.LinkNotFoundError
		vanished := errors.As(err, &notFound)
		if err != nil && !vanished {
			log.Printf("[%v] ipip iface %s lookup failed transiently (%v); will retry",
				srv.BindAddr, s.ifname, err)
			continue
		}

		srv.ipipMu.Lock()
		current, ok := srv.ipipPeers[s.clientIP]
		if !ok || current != s.peer {
			srv.ipipMu.Unlock()
			continue
		}
		if vanished {
			delete(srv.ipipPeers, s.clientIP)
			log.Printf("[%v] removing vanished ipip peer %v at %v",
				srv.BindAddr, s.clientIP, s.peer.peerIP)
			srv.dropIpipPeerLocked(s.peer)
			srv.ipipMu.Unlock()
			continue
		}
		stats := link.Attrs().Statistics
		var rx, tx uint64
		if stats != nil {
			rx = stats.RxBytes
			tx = stats.TxBytes
		}
		if rx != current.rxBytes || tx != current.txBytes {
			current.rxBytes = rx
			current.txBytes = tx
			current.lastSeen = now
		}
		if now.Sub(current.lastSeen) > PeerIdleTimeout {
			delete(srv.ipipPeers, s.clientIP)
			log.Printf("[%v] removing idle ipip peer %v at %v",
				srv.BindAddr, s.clientIP, current.peerIP)
			srv.dropIpipPeerLocked(current)
		}
		srv.ipipMu.Unlock()
	}
}

// CleanupIpip tears down every IPIP interface this server created. It is
// safe to call multiple times.
func (srv *Server) CleanupIpip() {
	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	srv.ipipClosed = true
	peers := make([]*ipipPeer, 0, len(srv.ipipPeers))
	for _, p := range srv.ipipPeers {
		peers = append(peers, p)
	}
	srv.ipipPeers = make(map[netip.Addr]*ipipPeer)
	for _, p := range peers {
		srv.dropIpipPeerLocked(p)
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
