package lib

import (
	"encoding/hex"
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

	lastSeen time.Time // last /connect-ipip or restore time
	rxBytes  uint64
	txBytes  uint64

	// espSpiToServer/ToClient are the SPIs of the pair's current ESP SAs,
	// or 0 for plaintext peers (and adopted peers, whose SPIs live only in
	// the kernel until the client re-keys). Kept for log lines and as the
	// rekey GC keep-set; the keys themselves are never stored beyond an
	// in-flight rekey (see espPendingToClient).
	espSpiToServer uint32
	espSpiToClient uint32

	// espRekeyEpoch increments on every request that changes the pair's
	// ESP state (rekey mint, destructive replace, plaintext strip) and on
	// teardown. The background switch/GC goroutines spawned by a rekey
	// capture the epoch and abort once superseded, so a stale poller can
	// never install or delete SAs that belong to a newer request.
	espRekeyEpoch uint64

	// espPendingToClient is the freshly minted outbound SA of an in-flight
	// rekey. It is held (keys included) only until the switch installs it
	// -- when the client's first packet arrives on the new inbound SA, or
	// on switch timeout -- and is cleared when superseded.
	espPendingToClient *ipipEspSA

	// espPrevSpiToServer is the previous inbound generation protected
	// from this epoch's GC (the client's rollback target; see
	// ipipEspGcLoop). espPrevSpiToClient is the previous outbound SPI,
	// kept for log lines only.
	espPrevSpiToServer uint32
	espPrevSpiToClient uint32
}

type connectIpipResponse struct {
	AssignedAddr string
	// Esp is present only when the request asked for it; old clients see
	// exactly the pre-ESP response shape.
	Esp *connectIpipEspResponse `json:",omitempty"`
}

// connectIpipEspResponse carries the minted SA material to the client over
// the TLS control channel. Keys are lowercase hex.
type connectIpipEspResponse struct {
	Algorithm       string
	SpiToServer     uint32
	EncKeyToServer  string
	AuthKeyToServer string
	SpiToClient     uint32
	EncKeyToClient  string
	AuthKeyToClient string
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

// ipipPeerFromIfname is the inverse of ipipIfname: it recovers the peer's
// inner IP from a "vp<srv.Index>-<offset>" interface name. Restore uses it
// to adopt leftover tunnels (and to identify invalid leftovers to delete).
// Returns false if the name does not belong to this server's IPIP interfaces.
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

// ipipRestoreKind is the restore planner's decision for one leftover iface.
type ipipRestoreKind int

const (
	ipipRestoreIgnore ipipRestoreKind = iota // name is not this server's vp<idx>-*
	ipipRestoreAdopt
	ipipRestoreDelete
)

const (
	ipipRestoreReasonNotIptun        = "not an iptun device"
	ipipRestoreReasonUnusableRemote  = "missing or unusable remote"
	ipipRestoreReasonDuplicateRemote = "duplicate remote"
	ipipRestoreReasonClaimFailed     = "inner IP already claimed or outside prefix"
)

// ipipRestoreCandidate is one leftover iface after name/type/remote
// classification. Kind may be upgraded from adopt to delete by planIpipRestore.
type ipipRestoreCandidate struct {
	Ifname string
	PeerIP netip.Addr
	Remote netip.Addr // outer/client IP; zero if unusable
	Kind   ipipRestoreKind
	Reason string
}

// usableIpipRemote reports whether an Iptun Remote is a specified IPv4
// address that can key ipipPeers.
func usableIpipRemote(remote net.IP) (netip.Addr, bool) {
	if len(remote) == 0 {
		return netip.Addr{}, false
	}
	ipv4 := remote.To4()
	if ipv4 == nil {
		return netip.Addr{}, false
	}
	addr := netip.AddrFrom4([4]byte{ipv4[0], ipv4[1], ipv4[2], ipv4[3]})
	if addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

// classifyIpipLink decides whether a leftover iface is ours to ignore, adopt,
// or delete, based only on name parseability, link type, and Remote.
// Duplicate Remote and Claim failures are applied later by planIpipRestore.
func classifyIpipLink(ifname string, isIptun bool, remote net.IP, parse func(string) (netip.Addr, bool)) ipipRestoreCandidate {
	peerIP, ok := parse(ifname)
	if !ok {
		return ipipRestoreCandidate{Ifname: ifname, Kind: ipipRestoreIgnore}
	}
	c := ipipRestoreCandidate{Ifname: ifname, PeerIP: peerIP}
	if !isIptun {
		c.Kind = ipipRestoreDelete
		c.Reason = ipipRestoreReasonNotIptun
		return c
	}
	addr, ok := usableIpipRemote(remote)
	if !ok {
		c.Kind = ipipRestoreDelete
		c.Reason = ipipRestoreReasonUnusableRemote
		return c
	}
	c.Remote = addr
	c.Kind = ipipRestoreAdopt
	return c
}

// planIpipRestore applies Claim and duplicate-Remote rules to classified
// candidates. Adoptables that lose Claim or collide on Remote become deletes.
// claim is called only for would-adopt candidates, in list order. The first
// successful Claim for a given Remote is kept; later collisions are deleted
// without claiming their inner IP.
func planIpipRestore(candidates []ipipRestoreCandidate, claim func(netip.Addr) bool) (adopt, del []ipipRestoreCandidate) {
	seenRemote := make(map[netip.Addr]struct{})
	for _, c := range candidates {
		switch c.Kind {
		case ipipRestoreIgnore:
			continue
		case ipipRestoreDelete:
			del = append(del, c)
		case ipipRestoreAdopt:
			if _, dup := seenRemote[c.Remote]; dup {
				c.Kind = ipipRestoreDelete
				c.Reason = ipipRestoreReasonDuplicateRemote
				del = append(del, c)
				continue
			}
			if !claim(c.PeerIP) {
				c.Kind = ipipRestoreDelete
				c.Reason = ipipRestoreReasonClaimFailed
				del = append(del, c)
				continue
			}
			seenRemote[c.Remote] = struct{}{}
			adopt = append(adopt, c)
		}
	}
	return adopt, del
}

// RestoreIpipFromKernel adopts leftover IPIP tunnels into Go state and
// deletes only invalid leftovers. Analogous to RestorePeersFromKernel: the
// kernel dataplane keeps forwarding across deploys, and Mac clients cache
// gif with no keepalive, so deleting a valid vp* on restart would black
// them out. A leftover 10.100.x/32 on an IPIP iface wins over WireGuard's
// connected /16, so invalid leftovers must still be removed (and those
// deletes must succeed) before we become ready.
//
// Restore runs once at startup, after RestorePeersFromKernel (so WireGuard
// claims win if both somehow own the same inner IP) and before
// ListenForHttps. There are no concurrent /connect-ipip handlers yet, so
// LinkList and orphan teardown do not take ipipMu; the lock is taken only
// to insert restored peers into ipipPeers.
func (srv *Server) RestoreIpipFromKernel() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links for ipip restore: %v", err)
	}

	classified := make([]ipipRestoreCandidate, 0, len(links))
	for _, link := range links {
		tun, isIptun := link.(*netlink.Iptun)
		var remote net.IP
		if isIptun {
			remote = tun.Remote
		}
		classified = append(classified, classifyIpipLink(
			link.Attrs().Name, isIptun, remote, srv.ipipPeerFromIfname))
	}

	adopt, del := planIpipRestore(classified, srv.ipAllocator.Claim)

	now := time.Now()
	srv.ipipMu.Lock()
	for _, c := range adopt {
		srv.ipipPeers[c.Remote] = &ipipPeer{
			clientIP: c.Remote,
			peerIP:   c.PeerIP,
			ifname:   c.Ifname,
			lastSeen: now,
		}
	}
	srv.ipipMu.Unlock()

	if len(adopt) > 0 {
		log.Printf("[%v] restored %d ipip tunnel(s) from kernel",
			srv.BindAddr, len(adopt))
	}

	for _, c := range adopt {
		log.Printf("[%v] restored ipip tunnel %s (peer %v, remote %v)",
			srv.BindAddr, c.Ifname, c.PeerIP, c.Remote)
		if err := srv.addIpipPeerFilter(c.Ifname, c.PeerIP); err != nil {
			return fmt.Errorf("restore ipip filter for %s: %v", c.Ifname, err)
		}
	}

	for _, c := range del {
		log.Printf("[%v] removing invalid leftover ipip iface %s (peer %v): %s",
			srv.BindAddr, c.Ifname, c.PeerIP, c.Reason)
		if err := srv.tearDownIpipLink(c.Ifname, c.PeerIP); err != nil {
			return fmt.Errorf("tear down invalid ipip leftover %s: %v", c.Ifname, err)
		}
		// Adopted pairs keep their kernel xfrm untouched (the SAs keep
		// encrypting across the restart); deleted leftovers lose theirs.
		if c.Remote.IsValid() {
			if err := srv.removeIpipEsp(c.Remote); err != nil {
				log.Printf("[%v] failed to remove esp for deleted ipip leftover %s (client %v): %v",
					srv.BindAddr, c.Ifname, c.Remote, err)
			}
		}
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

	req, err := parseConnectIpipRequest(r.Body)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := req.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, errMsg, errStatus := srv.lookupOrCreateIpip(clientIP, req)
	if errMsg != "" {
		http.Error(w, errMsg, errStatus)
		return
	}
	writeIpipResponse(w, resp)
}

// lookupOrCreateIpip returns the connect response for clientIP, creating the
// kernel tunnel if needed and installing (or removing) the pair's ESP state
// per the request. It holds ipipMu for the whole lookup/create so the peer
// map and the kernel (local, remote) pair stay in lockstep, and so ESP state
// is installed before the HTTP response is written by the caller.
func (srv *Server) lookupOrCreateIpip(clientIP netip.Addr, req connectIpipRequest) (resp *connectIpipResponse, errMsg string, errStatus int) {
	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	if srv.ipipClosed {
		return nil, "server shutting down", http.StatusServiceUnavailable
	}

	if existing, ok := srv.ipipPeers[clientIP]; ok {
		// Only a genuine "not found" counts as vanished. A transient
		// lookup failure must not tear down a working tunnel.
		_, lookupErr := netlink.LinkByName(existing.ifname)
		vanished := ipipLinkNotFound(lookupErr)
		if lookupErr != nil && !vanished {
			log.Printf("[%v] ipip iface %s lookup failed transiently (%v); reusing",
				srv.BindAddr, existing.ifname, lookupErr)
		}
		if !vanished {
			existing.lastSeen = time.Now()
			return srv.finishIpipConnectLocked(existing, req)
		}
		log.Printf("[%v] ipip iface %s for %v vanished; rebuilding",
			srv.BindAddr, existing.ifname, clientIP)
		if err := srv.dropIpipPeerLocked(existing); err != nil {
			log.Printf("[%v] failed to tear down vanished ipip iface %s for %v: %v; leaving in place",
				srv.BindAddr, existing.ifname, clientIP, err)
			return nil, "failed to rebuild IPIP tunnel", http.StatusInternalServerError
		}
		delete(srv.ipipPeers, clientIP)
	}

	peer, errMsg, errStatus := srv.createIpipPeerLocked(clientIP)
	if errMsg != "" {
		return nil, errMsg, errStatus
	}
	return srv.finishIpipConnectLocked(peer, req)
}

// finishIpipConnectLocked applies the request's ESP choice to an existing or
// freshly created peer and builds the response. Caller must hold ipipMu.
//
// esp (without rekey) mints a fresh SA pair and replaces whatever the
// kernel holds for the pair -- the destructive fresh-connect semantics.
// esp+rekey rotates SA generations additively (see the package comment in
// ipip_esp.go). Plaintext removes any leftover ESP state so an old (or
// rolled-back) client gets exactly today's behavior instead of a
// require-ESP policy blackholing it.
//
// Every branch bumps espRekeyEpoch first, so any in-flight rekey
// switch/GC goroutine from a previous request aborts instead of touching
// state that this request supersedes.
func (srv *Server) finishIpipConnectLocked(p *ipipPeer, req connectIpipRequest) (resp *connectIpipResponse, errMsg string, errStatus int) {
	resp = &connectIpipResponse{
		AssignedAddr: fmt.Sprintf("%v/%d", p.peerIP, srv.WgCidr.Bits()),
	}

	p.espRekeyEpoch++
	p.espPendingToClient = nil

	if !req.Esp {
		if err := srv.removeIpipEsp(p.clientIP); err != nil {
			log.Printf("[%v] esp remove FAILED for plaintext ipip peer %v (%s): %v",
				srv.BindAddr, p.clientIP, p.ifname, err)
			return nil, "failed to remove stale ESP state", http.StatusInternalServerError
		}
		p.espSpiToServer, p.espSpiToClient = 0, 0
		p.espPrevSpiToServer, p.espPrevSpiToClient = 0, 0
		return resp, "", 0
	}

	keys, err := mintIpipEspKeys()
	if err != nil {
		log.Printf("[%v] esp key minting failed for ipip peer %v: %v",
			srv.BindAddr, p.clientIP, err)
		return nil, "failed to mint ESP keys", http.StatusInternalServerError
	}

	if req.Rekey {
		if err := srv.rekeyIpipEsp(p, keys); err != nil {
			log.Printf("[%v] esp rekey FAILED for ipip peer %v (%s): %v",
				srv.BindAddr, p.clientIP, p.ifname, err)
			return nil, "failed to rekey ESP", http.StatusInternalServerError
		}
	} else {
		if err := srv.installIpipEsp(p.clientIP, p.ifname, keys); err != nil {
			log.Printf("[%v] esp install FAILED for ipip peer %v (%s): %v",
				srv.BindAddr, p.clientIP, p.ifname, err)
			return nil, "failed to install ESP", http.StatusInternalServerError
		}
		p.espSpiToServer, p.espSpiToClient = keys.ToServer.Spi, keys.ToClient.Spi
		p.espPrevSpiToServer, p.espPrevSpiToClient = 0, 0
		log.Printf("[%v] esp installed for ipip peer %v (%s, spi to-server 0x%x, to-client 0x%x, alg %s)",
			srv.BindAddr, p.clientIP, p.ifname, keys.ToServer.Spi, keys.ToClient.Spi, ipipEspAlgorithm)
	}

	resp.Esp = &connectIpipEspResponse{
		Algorithm:       ipipEspAlgorithm,
		SpiToServer:     keys.ToServer.Spi,
		EncKeyToServer:  hex.EncodeToString(keys.ToServer.EncKey),
		AuthKeyToServer: hex.EncodeToString(keys.ToServer.AuthKey),
		SpiToClient:     keys.ToClient.Spi,
		EncKeyToClient:  hex.EncodeToString(keys.ToClient.EncKey),
		AuthKeyToClient: hex.EncodeToString(keys.ToClient.AuthKey),
	}
	return resp, "", 0
}

// createIpipPeerLocked allocates an inner IP, creates the IPIP tunnel, and
// registers the peer. Caller must hold ipipMu. On failure it returns a
// non-empty errMsg and HTTP status.
func (srv *Server) createIpipPeerLocked(clientIP netip.Addr) (peer *ipipPeer, errMsg string, errStatus int) {
	if winner, ok := srv.ipipPeers[clientIP]; ok {
		winner.lastSeen = time.Now()
		return winner, "", 0
	}
	if srv.ipipClosed {
		return nil, "server shutting down", http.StatusServiceUnavailable
	}

	peerIP := srv.ipAllocator.Allocate()
	if peerIP.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		return nil, "no more IP addresses available", http.StatusServiceUnavailable
	}

	ifname, err := srv.ipipIfname(peerIP)
	if err != nil {
		srv.ipAllocator.Free(peerIP)
		log.Printf("[%v] %v", srv.BindAddr, err)
		return nil, "ipip ifname out of range", http.StatusInternalServerError
	}
	if err := srv.createIpipLink(ifname, clientIP, peerIP); err != nil {
		if srv.freeIpipIPIfIfaceGone(ifname, peerIP) {
			log.Printf("[%v] failed to create IPIP tunnel for %v: %v",
				srv.BindAddr, clientIP, err)
		} else {
			log.Printf("[%v] failed to create IPIP tunnel for %v: %v; iface %s may still exist, leaving %v allocated",
				srv.BindAddr, clientIP, err, ifname, peerIP)
		}
		return nil, "failed to create IPIP tunnel", http.StatusInternalServerError
	}

	peer = &ipipPeer{
		clientIP: clientIP,
		peerIP:   peerIP,
		ifname:   ifname,
		lastSeen: time.Now(),
	}
	srv.ipipPeers[clientIP] = peer

	log.Printf("[%v] new ipip peer %v at %v (iface %s)",
		srv.BindAddr, clientIP, peerIP, ifname)

	return peer, "", 0
}

// dropIpipPeerLocked tears down p's kernel objects and, only after the
// iface is confirmed gone, frees its inner IP. Caller must hold ipipMu
// and must not have deleted p from ipipPeers yet. On error the map entry,
// allocator claim, and kernel iface are left as-is.
func (srv *Server) dropIpipPeerLocked(p *ipipPeer) error {
	if err := srv.tearDownIpipLink(p.ifname, p.peerIP); err != nil {
		return err
	}
	// ESP removal is best-effort: a leftover SA/policy for a gone pair
	// cannot blackhole anyone else's traffic (the selector is scoped to
	// this client pair) and is replaced on the client's next connect.
	if err := srv.removeIpipEsp(p.clientIP); err != nil {
		log.Printf("[%v] esp remove FAILED during teardown of ipip peer %v (%s, spi to-server 0x%x, to-client 0x%x): %v; continuing",
			srv.BindAddr, p.clientIP, p.ifname, p.espSpiToServer, p.espSpiToClient, err)
	} else if p.espSpiToServer != 0 {
		log.Printf("[%v] esp removed for ipip peer %v (%s, spi to-server 0x%x, to-client 0x%x)",
			srv.BindAddr, p.clientIP, p.ifname, p.espSpiToServer, p.espSpiToClient)
	}
	srv.ipAllocator.Free(p.peerIP)
	return nil
}

// freeIpipIPIfIfaceGone Frees peerIP only if ifname is confirmed absent
// (LinkNotFound). Any other LinkByName result means the kernel object may
// still hold the /32, so the address stays allocated. Returns true if the
// IP was freed.
func (srv *Server) freeIpipIPIfIfaceGone(ifname string, peerIP netip.Addr) bool {
	_, err := netlink.LinkByName(ifname)
	if ipipLinkNotFound(err) {
		srv.ipAllocator.Free(peerIP)
		return true
	}
	if err != nil {
		log.Printf("[%v] ipip iface %s lookup failed during create rollback (%v); leaving %v allocated",
			srv.BindAddr, ifname, err, peerIP)
		return false
	}
	log.Printf("[%v] ipip iface %s still exists after create failure; leaving %v allocated",
		srv.BindAddr, ifname, peerIP)
	return false
}

// ipipLinkNotFound reports a genuine missing iface. Only this error means
// the kernel object is gone and its inner IP may be Freed. A nil error
// (iface exists) or any other lookup failure means the /32 may still be
// installed.
func ipipLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}

func writeIpipResponse(w http.ResponseWriter, resp *connectIpipResponse) {
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
		Scope:     netlinkScopeLink,
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
// interface. The interface is the source of truth: LinkNotFound is success
// (already gone), any other lookup or LinkDel error is returned so the
// caller does not Free the inner IP or drop the map entry. Filter removal
// is best-effort; a surviving iface is not treated as torn down.
func (srv *Server) tearDownIpipLink(ifname string, peerIP netip.Addr) error {
	srv.removeIpipPeerFilter(ifname, peerIP)

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		if ipipLinkNotFound(err) {
			return nil
		}
		return fmt.Errorf("lookup ipip link %s: %v", ifname, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete ipip link %s: %v", ifname, err)
	}
	return nil
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

func (srv *Server) removeVanishedIpipPeersLoop() {
	for {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		srv.removeVanishedIpipPeers()
	}
}

// removeVanishedIpipPeers reaps IPIP peers whose kernel iface is already
// gone. Mac clients have no keepalive and cache gif across a quiet VM, so
// we must not delete a living tunnel after PeerIdleTimeout — that would
// blackhole return traffic the same way a restart sweep of valid vp* does.
//
// If the kernel already deleted vp*, tearing down filters and Freeing the
// inner IP is correct: there is no leftover /32. Lookups run without
// ipipMu so a full scan does not stall handshakes. Teardown, Free, and map
// delete run under the lock, in that order; a teardown error leaves the
// map entry and allocator claim in place for the next tick.
func (srv *Server) removeVanishedIpipPeers() {
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

	for _, s := range snaps {
		_, err := netlink.LinkByName(s.ifname)
		if err != nil && !ipipLinkNotFound(err) {
			log.Printf("[%v] ipip iface %s lookup failed transiently (%v); will retry",
				srv.BindAddr, s.ifname, err)
			continue
		}
		if err == nil {
			continue
		}

		srv.ipipMu.Lock()
		current, ok := srv.ipipPeers[s.clientIP]
		if !ok || current != s.peer {
			srv.ipipMu.Unlock()
			continue
		}
		if err := srv.dropIpipPeerLocked(s.peer); err != nil {
			log.Printf("[%v] failed to tear down vanished ipip peer %v at %v (%s): %v; will retry",
				srv.BindAddr, s.clientIP, s.peer.peerIP, s.peer.ifname, err)
			srv.ipipMu.Unlock()
			continue
		}
		delete(srv.ipipPeers, s.clientIP)
		log.Printf("[%v] removed vanished ipip peer %v at %v",
			srv.BindAddr, s.clientIP, s.peer.peerIP)
		srv.ipipMu.Unlock()
	}
}

// CleanupIpip tears down every IPIP interface this server created. It is
// available for manual decommissioning (like CleanupWireguard) and is not
// called on process shutdown: the kernel dataplane keeps forwarding across
// deploys. Safe to call multiple times. A teardown error leaves that peer's
// map entry and allocator claim in place.
func (srv *Server) CleanupIpip() {
	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	srv.ipipClosed = true
	for clientIP, p := range srv.ipipPeers {
		if err := srv.dropIpipPeerLocked(p); err != nil {
			log.Printf("[%v] failed to decommission ipip peer %v (%s): %v; leaving in place",
				srv.BindAddr, clientIP, p.ifname, err)
			continue
		}
		delete(srv.ipipPeers, clientIP)
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
