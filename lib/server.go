package lib

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// FwmarkBase is the base value for firewall marks used by vprox.
const FwmarkBase = 0x54437D00

// UDP listen port base value for WireGuard connections.
const WireguardListenPortBase = 50227

// A new peer must connect with a handshake within this time.
const FirstHandshakeTimeout = 10 * time.Second

// If no handshakes are received in this time, the peer is considered idle and
// removed from the server's WireGuard interface list.
//
// Note that this must be at least 2-3 minutes, since WireGuard sends handshakes
// interleaved with a data message only when 2-3 minutes have passed since the
// last successful handshake. This is regardless of the persistent-keepalive
// setting.
const PeerIdleTimeout = 5 * time.Minute

// After a /connect, the idle reaper leaves the peer alone for this long even
// if its last handshake is stale. This covers the window between the handler
// resolving the peer's IP and writing it to the device, plus the client's
// subsequent handshake and health checks, so the reaper can't free an IP that
// an in-flight or just-completed /connect is using.
const ConnectGracePeriod = 1 * time.Minute

// Server handles state for one WireGuard network.
//
// The `vprox server` command should create one Server instance for each
// private IP that the server should bind to.
type Server struct {
	// Key is the private key of the server.
	Key wgtypes.Key

	// BindAddr is the private IPv4 address that the server binds to.
	BindAddr netip.Addr

	// BindIface is the interface that the address is bound to, and it's also
	// the interface for outbound VPN traffic after masquerade.
	//
	// Currently only setting this to the default interface is supported.
	BindIface netlink.Link

	// InternalBindIface is the interface for internal network traffic.
	InternalBindIface netlink.Link

	// InternalNetworkCidr is the CIDR block of the internal network.
	InternalNetworkCidr string

	// Password is needed to authenticate connection requests.
	Password string

	// Index is a unique server index for firewall marks and other uses. It starts at 0.
	Index uint16

	// Ipt is the iptables client for managing firewall rules.
	Ipt *iptables.IPTables

	// WgClient is a shared client for interacting with the WireGuard kernel module.
	WgClient *wgctrl.Client

	// WgCidr is the CIDR block of IPs that the server assigns to WireGuard peers.
	WgCidr netip.Prefix

	// Ctx is the shutdown context for the server.
	Ctx context.Context

	// Region is the region of the server.
	Region string

	ipAllocator *IpAllocator

	mu sync.Mutex // Protects the fields below.
	// newPeers records the time of each peer's most recent /connect, granting
	// a grace period during which the idle reaper won't remove the peer. This
	// protects peers that haven't completed a WireGuard handshake yet, and
	// prevents the reaper from racing an in-flight /connect (reaping a peer and
	// freeing its IP between the handler's IP resolution and its device write).
	newPeers map[wgtypes.Key]time.Time
	// peerIPs is the authoritative in-memory index of the IP assigned to each
	// configured peer. It lets connectHandler resolve an existing peer's IP
	// without dumping the entire WireGuard device (an O(peers) netlink call)
	// on every /connect request. It is kept in sync with ipAllocator and the
	// kernel device: an entry is added when a peer is allocated an IP and
	// removed when the reaper deletes an idle peer.
	peerIPs map[wgtypes.Key]netip.Addr

	// ipipMu protects ipipPeers. It is separate from mu so that the IPIP
	// peer bookkeeping does not contend with the WireGuard peer state.
	ipipMu    sync.Mutex
	ipipPeers map[netip.Addr]*ipipPeer
}

// InitState initializes the private server state.
func (srv *Server) InitState() error {
	if srv.BindIface == nil {
		iface, err := getDefaultInterface()
		if err != nil {
			return err
		}
		srv.BindIface = iface
	}
	if srv.Region == "us-west" && srv.InternalBindIface == nil {
		iface, err := getInternalInterface()
		if err != nil {
			return err
		}
		srv.InternalBindIface = iface
	}

	srv.ipAllocator = NewIpAllocator(srv.WgCidr)
	// Reserve the first IP address for the server itself.
	reservedIp := srv.ipAllocator.Allocate()
	if reservedIp != srv.WgCidr.Addr() {
		return fmt.Errorf("reserved IP address mistamches CIDR: %v != %v", reservedIp, srv.WgCidr.Addr())
	}
	srv.newPeers = make(map[wgtypes.Key]time.Time)
	srv.peerIPs = make(map[wgtypes.Key]netip.Addr)
	srv.ipipPeers = make(map[netip.Addr]*ipipPeer)
	return nil
}

func (srv *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintf(w, "vprox ok. received %v -> %v:443\n", r.RemoteAddr, srv.BindAddr)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type connectRequest struct {
	PeerPublicKey string
}
type connectResponse struct {
	AssignedAddr     string
	ServerPublicKey  string
	ServerListenPort int
}

// Handle a new connection.
func (srv *Server) connectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+srv.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req := &connectRequest{}
	if err = json.Unmarshal(buf, req); err != nil {
		http.Error(w, "failed to parse request body", http.StatusBadRequest)
		return
	}

	peerKey, err := wgtypes.ParseKey(req.PeerPublicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid peer public key: %v", err), http.StatusBadRequest)
		return
	}

	// Resolve the peer's IP. If it already has one, reuse it; otherwise
	// allocate a new one. This is done under the lock using the in-memory
	// peerIPs index so we avoid an O(peers) WireGuard device dump on the
	// /connect hot path.
	srv.mu.Lock()
	peerIp, isExisting := srv.peerIPs[peerKey]
	if !isExisting {
		peerIp = srv.ipAllocator.Allocate()
		if peerIp.IsUnspecified() {
			srv.mu.Unlock()
			log.Printf("no more ip addresses available in %v", srv.WgCidr)
			http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
			return
		}
		srv.peerIPs[peerKey] = peerIp
	}
	// Refresh the grace period before the idle reaper may remove this peer,
	// covering both brand-new peers and reconnecting ones.
	srv.newPeers[peerKey] = time.Now()
	srv.mu.Unlock()

	clientIp := strings.Split(r.RemoteAddr, ":")[0] // for logging
	if !isExisting {
		log.Printf("[%v] new peer %v at %v: %v", srv.BindAddr, clientIp, peerIp, peerKey)
	}
	err = srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{prefixToIPNet(netip.PrefixFrom(peerIp, 32))},
			},
		},
	})
	if err != nil {
		// Roll back the allocation we just made so state stays consistent.
		if !isExisting {
			srv.mu.Lock()
			delete(srv.peerIPs, peerKey)
			delete(srv.newPeers, peerKey)
			srv.mu.Unlock()
			srv.ipAllocator.Free(peerIp)
		}
		log.Printf("failed to configure WireGuard peer: %v", err)
		http.Error(w, "failed to configure WireGuard peer", http.StatusInternalServerError)
		return
	}

	// Return the assigned IP address and the server's public key.
	resp := &connectResponse{
		AssignedAddr:     fmt.Sprintf("%v/%d", peerIp, srv.WgCidr.Bits()),
		ServerPublicKey:  srv.Key.PublicKey().String(),
		ServerListenPort: WireguardListenPortBase + int(srv.Index),
	}

	respBuf, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBuf)
}

func (srv *Server) Ifname() string {
	return fmt.Sprintf("vprox%d", srv.Index)
}

// StartWireguard brings up the server's WireGuard interface.
//
// If an interface with the expected name already exists (e.g. left behind by
// a previous vprox process across a restart), it is adopted rather than
// recreated, so that its kernel peer list, and therefore the tunnels of every
// registered peer, survive the restart. The interface is only deleted and
// recreated if its address doesn't match the expected CIDR, as a safety net
// for configuration changes.
func (srv *Server) StartWireguard() error {
	ifname := srv.Ifname()

	link, err := netlink.LinkByName(ifname)
	if err == nil {
		if srv.canAdoptLink(link) {
			log.Printf("[%v] adopting existing WireGuard device %s", srv.BindAddr, ifname)
		} else {
			log.Printf("[%v] existing device %s doesn't match config; recreating it",
				srv.BindAddr, ifname)
			_ = netlink.LinkDel(link)
			link = nil
		}
	} else {
		link = nil
	}

	created := false
	if link == nil {
		wgLink := &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return fmt.Errorf("failed to create WireGuard device: %v", err)
		}
		link = wgLink
		created = true
	}

	// The remaining steps are non-destructive to existing peers: AddrReplace
	// is idempotent, and ConfigureDevice without ReplacePeers leaves the
	// kernel peer list untouched. On failure, only delete the device if we
	// created it ourselves; deleting an adopted device would kill live
	// tunnels.
	cleanupOnError := func() {
		if created {
			_ = netlink.LinkDel(link)
		}
	}

	ipnet := prefixToIPNet(srv.WgCidr)
	err = netlink.AddrReplace(link, &netlink.Addr{IPNet: &ipnet})
	if err != nil {
		cleanupOnError()
		return fmt.Errorf("failed to add address to WireGuard device: %v", err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		cleanupOnError()
		return fmt.Errorf("failed to bring up WireGuard device: %v", err)
	}

	listenPort := WireguardListenPortBase + int(srv.Index)
	err = srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey: &srv.Key,
		ListenPort: &listenPort,
	})
	if err != nil {
		cleanupOnError()
		return err
	}

	return nil
}

// canAdoptLink reports whether an existing link can be adopted as this
// server's WireGuard interface: it must be a WireGuard device whose address
// matches the server's peer CIDR.
func (srv *Server) canAdoptLink(link netlink.Link) bool {
	if link.Type() != "wireguard" {
		return false
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return false
	}
	want := prefixToIPNet(srv.WgCidr)
	wantOnes, _ := want.Mask.Size()
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		ones, _ := addr.Mask.Size()
		if addr.IP.Equal(want.IP) && ones == wantOnes {
			return true
		}
	}
	return false
}

// restoredPeers holds the result of rebuilding in-memory peer state from a
// kernel WireGuard device dump.
type restoredPeers struct {
	// peerIPs maps each valid peer to its assigned IP.
	peerIPs map[wgtypes.Key]netip.Addr
	// invalid lists peers whose AllowedIPs don't encode a valid assigned IP;
	// they should be removed from the device.
	invalid []wgtypes.Key
}

// restorePeerState rebuilds peer-to-IP assignments from a kernel WireGuard
// peer list, claiming each assigned IP in the allocator. A peer is valid if
// its first AllowedIP is an IPv4 /32 whose address can be claimed (inside the
// allocator's prefix and not already taken). Invalid peers are returned for
// removal so in-memory state and the kernel device stay consistent.
func restorePeerState(peers []wgtypes.Peer, alloc *IpAllocator) restoredPeers {
	result := restoredPeers{peerIPs: make(map[wgtypes.Key]netip.Addr)}
	for _, peer := range peers {
		addr, ok := peerAssignedIp(peer)
		if !ok || !alloc.Claim(addr) {
			result.invalid = append(result.invalid, peer.PublicKey)
			continue
		}
		result.peerIPs[peer.PublicKey] = addr
	}
	return result
}

// peerAssignedIp extracts the IP assigned to a peer from its AllowedIPs,
// which vprox always writes as a single IPv4 /32.
func peerAssignedIp(peer wgtypes.Peer) (netip.Addr, bool) {
	if len(peer.AllowedIPs) == 0 {
		return netip.Addr{}, false
	}
	ipnet := peer.AllowedIPs[0]
	ipv4 := ipnet.IP.To4()
	if ipv4 == nil {
		return netip.Addr{}, false
	}
	if ones, bits := ipnet.Mask.Size(); ones != 32 || bits != 32 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(ipv4)), true
}

// RestorePeersFromKernel rebuilds the in-memory peer index (peerIPs,
// ipAllocator, newPeers) from the kernel WireGuard device's peer list. It is
// called once on startup, after StartWireguard adopts an interface that
// survived a restart, so that:
//
//   - existing peers keep their IPs and the allocator never hands an
//     already-assigned IP to a new peer (which would silently steal the
//     existing peer's AllowedIPs routing and blackhole it), and
//   - the idle reaper grants restored peers the usual grace period instead of
//     instantly reaping ones whose last handshake predates the restart.
func (srv *Server) RestorePeersFromKernel() error {
	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}
	if len(device.Peers) == 0 {
		return nil
	}

	restored := restorePeerState(device.Peers, srv.ipAllocator)

	now := time.Now()
	srv.mu.Lock()
	for key, addr := range restored.peerIPs {
		srv.peerIPs[key] = addr
		srv.newPeers[key] = now
	}
	srv.mu.Unlock()

	if len(restored.peerIPs) > 0 {
		log.Printf("[%v] restored %d peer(s) from existing WireGuard device",
			srv.BindAddr, len(restored.peerIPs))
	}

	// Remove peers with missing or malformed AllowedIPs from the device.
	// These shouldn't exist, but dropping them keeps in-memory state
	// consistent with the kernel.
	if len(restored.invalid) > 0 {
		removals := make([]wgtypes.PeerConfig, 0, len(restored.invalid))
		for _, key := range restored.invalid {
			log.Printf("[%v] removing peer with invalid allowed IPs during restore: %v",
				srv.BindAddr, key)
			removals = append(removals, wgtypes.PeerConfig{PublicKey: key, Remove: true})
		}
		err := srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{Peers: removals})
		if err != nil {
			return fmt.Errorf("failed to remove invalid peers: %v", err)
		}
	}
	return nil
}

func (srv *Server) CleanupWireguard() {
	ifname := srv.Ifname()
	_ = netlink.LinkDel(&linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}})
}

// iptablesInputFwmarkRule adds or removes the mangle PREROUTING rule for traffic from WireGuard.
func (srv *Server) iptablesInputFwmarkRule(enabled bool) error {
	firewallMark := FwmarkBase + int(srv.Index)
	rule := []string{
		"-i", srv.Ifname(),
		"-j", "MARK", "--set-mark", strconv.Itoa(firewallMark),
		"-m", "comment", "--comment", fmt.Sprintf("vprox fwmark rule for %s", srv.Ifname()),
	}
	if enabled {
		return srv.Ipt.AppendUnique("mangle", "PREROUTING", rule...)
	} else {
		return srv.Ipt.Delete("mangle", "PREROUTING", rule...)
	}
}

// iptablesSnatRule adds or removes the nat POSTROUTING rule for outbound traffic.
func (srv *Server) iptablesSnatRule(enabled bool) error {
	firewallMark := FwmarkBase + int(srv.Index)
	rule := []string{
		"-m", "mark", "--mark", strconv.Itoa(firewallMark),
		"-j", "SNAT", "--to-source", srv.BindAddr.String(),
		"-m", "comment", "--comment", fmt.Sprintf("vprox snat rule for %s", srv.Ifname()),
	}
	if enabled {
		return srv.Ipt.AppendUnique("nat", "POSTROUTING", rule...)
	} else {
		return srv.Ipt.Delete("nat", "POSTROUTING", rule...)
	}
}

// internalSnatRuleComment tags the nat POSTROUTING rule that SNATs traffic
// from the WireGuard subnet to the internal network.
const internalSnatRuleComment = "SNAT for WireGuard to internal network"

// staleInternalSnatRules returns the rule specs (the arguments after
// "-A POSTROUTING") of internal-network SNAT rules for wgCidr whose SNAT
// target is not bindAddr. rules is an `iptables -S` listing of nat
// POSTROUTING. Such rules survive a restart when a server index is reused
// with a different bind address; since AppendUnique adds the new rule after
// them, they would keep matching internal traffic and SNAT it to the stale
// address.
func staleInternalSnatRules(rules []string, wgCidr netip.Prefix, bindAddr netip.Addr) [][]string {
	// iptables normalizes the source to the masked network address.
	source := fmt.Sprintf("-s %s ", wgCidr.Masked().String())
	target := fmt.Sprintf("--to-source %s ", bindAddr.String())
	var specs [][]string
	for _, rule := range rules {
		padded := rule + " "
		if strings.Contains(padded, internalSnatRuleComment) &&
			strings.Contains(padded, source) &&
			!strings.Contains(padded, target) {
			if spec := iptablesRuleSpec(rule); spec != nil {
				specs = append(specs, spec)
			}
		}
	}
	return specs
}

// iptablesRuleSpec parses an `iptables -S` "-A <chain> ..." line into the
// rule's argument list (without the leading "-A <chain>"), suitable for a
// match-based delete. Double-quoted tokens (e.g. comments containing spaces)
// are unquoted and backslash escapes are resolved. Returns nil for lines that
// are not append rules, such as the "-P <chain> <policy>" line.
func iptablesRuleSpec(rule string) []string {
	var args []string
	var cur strings.Builder
	inQuotes := false
	escaped := false
	inToken := false
	for _, r := range rule {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
			inToken = true
		case r == ' ' && !inQuotes:
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if inToken {
		args = append(args, cur.String())
	}
	if len(args) < 2 || args[0] != "-A" {
		return nil
	}
	return args[2:]
}

// cleanupStaleInternalSnatRules removes internal-network SNAT rules for this
// server's WireGuard subnet that target a different bind address. Deletion is
// by exact rule match rather than by rule number: each server runs
// StartIptables in its own goroutine against the shared iptables handle, so
// deleting by number races with concurrent inserts/deletes shifting the
// numbering. Match-based deletes are unaffected, and rules for other servers'
// subnets never match this server's specs.
func (srv *Server) cleanupStaleInternalSnatRules() error {
	rules, err := srv.Ipt.List("nat", "POSTROUTING")
	if err != nil {
		return fmt.Errorf("failed to list nat POSTROUTING rules: %v", err)
	}
	for _, spec := range staleInternalSnatRules(rules, srv.WgCidr, srv.BindAddr) {
		log.Printf("[%v] removing stale internal SNAT rule: %v", srv.BindAddr, strings.Join(spec, " "))
		if err := srv.Ipt.DeleteIfExists("nat", "POSTROUTING", spec...); err != nil {
			return fmt.Errorf("failed to delete stale SNAT rule: %v", err)
		}
	}
	return nil
}

func (srv *Server) StartIptables() error {
	// Add masquerade rule for the outbound interface.
	rule := []string{
		"-o", srv.BindIface.Attrs().Name,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", fmt.Sprintf("vprox masquerade rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.AppendUnique("nat", "POSTROUTING", rule...); err != nil {
		return fmt.Errorf("failed to add masquerade rule: %v", err)
	}

	// Add rule to allow forwarding from WireGuard interface
	rule = []string{
		"-i", srv.Ifname(),
		"-j", "ACCEPT",
		"-m", "comment", "--comment", fmt.Sprintf("vprox forward rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.AppendUnique("filter", "FORWARD", rule...); err != nil {
		return fmt.Errorf("failed to add forward rule: %v", err)
	}

	// Add TCP MSS clamping rules for both directions
	tcpMssRule := []string{
		"-o", srv.Ifname(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment", "--comment", fmt.Sprintf("vprox TCP MSS outbound rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.AppendUnique("mangle", "FORWARD", tcpMssRule...); err != nil {
		return fmt.Errorf("failed to add outbound TCP MSS rule: %v", err)
	}

	tcpMssRule = []string{
		"-i", srv.Ifname(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment", "--comment", fmt.Sprintf("vprox TCP MSS inbound rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.AppendUnique("mangle", "FORWARD", tcpMssRule...); err != nil {
		return fmt.Errorf("failed to add inbound TCP MSS rule: %v", err)
	}

	// Wildcard TCP MSS clamping for this server's IPIP interfaces. The
	// interfaces themselves are created lazily by /connect-ipip; the
	// FORWARD ACCEPT/DROP filter is installed per peer at that point so
	// each tunnel only accepts traffic with the inner source IP we
	// assigned to it (see addIpipPeerFilter).
	if err := srv.iptablesIpipMssRules(true); err != nil {
		return fmt.Errorf("failed to add ipip MSS rules: %v", err)
	}

	// SNAT rule for internal network traffic. This is currently only applicable for boxes in
	// the US.
	if srv.Region == "us-west" {
		// Shutdown intentionally leaves iptables rules in place (see
		// ServerManager.Start), so if this server's index was previously
		// bound to a different address, a stale SNAT rule targeting the old
		// address would precede the one added below and keep matching
		// internal traffic. Remove any such rules first.
		if err := srv.cleanupStaleInternalSnatRules(); err != nil {
			return err
		}

		rule = []string{
			"-s", srv.WgCidr.String(),
			"-d", srv.InternalNetworkCidr,
			"-o", srv.InternalBindIface.Attrs().Name,
			"-j", "SNAT", "--to-source", srv.BindAddr.String(),
			"-m", "comment", "--comment", internalSnatRuleComment,
		}
		if err := srv.Ipt.AppendUnique("nat", "POSTROUTING", rule...); err != nil {
			return fmt.Errorf("failed to add SNAT rule: %v", err)
		}

		// FORWARD rule from WireGuard to internal network
		rule = []string{
			"-i", srv.Ifname(),
			"-o", srv.InternalBindIface.Attrs().Name,
			"-s", srv.WgCidr.String(),
			"-d", srv.InternalNetworkCidr,
			"-j", "ACCEPT",
			"-m", "comment", "--comment", "Forward from WireGuard to internal network",
		}
		if err := srv.Ipt.AppendUnique("filter", "FORWARD", rule...); err != nil {
			return fmt.Errorf("failed to add FORWARD rule: %v", err)
		}

		// FORWARD rule from internal network to WireGuard
		rule = []string{
			"-i", srv.InternalBindIface.Attrs().Name,
			"-o", srv.Ifname(),
			"-s", srv.InternalNetworkCidr,
			"-d", srv.WgCidr.String(),
			"-j", "ACCEPT",
			"-m", "comment", "--comment", "Forward from internal network to WireGuard",
		}
		if err := srv.Ipt.AppendUnique("filter", "FORWARD", rule...); err != nil {
			return fmt.Errorf("failed to add FORWARD rule: %v", err)
		}
	}

	return nil
}

func (srv *Server) CleanupIptables() {
	// Remove masquerade rule
	rule := []string{
		"-o", srv.BindIface.Attrs().Name,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", fmt.Sprintf("vprox masquerade rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.Delete("nat", "POSTROUTING", rule...); err != nil {
		log.Printf("failed to remove masquerade rule: %v", err)
	}

	// Remove forwarding rule
	rule = []string{
		"-i", srv.Ifname(),
		"-j", "ACCEPT",
		"-m", "comment", "--comment", fmt.Sprintf("vprox forward rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.Delete("filter", "FORWARD", rule...); err != nil {
		log.Printf("failed to remove forward rule: %v", err)
	}

	// Remove TCP MSS clamping rules
	tcpMssRule := []string{
		"-o", srv.Ifname(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment", "--comment", fmt.Sprintf("vprox TCP MSS outbound rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.Delete("mangle", "FORWARD", tcpMssRule...); err != nil {
		log.Printf("failed to remove outbound TCP MSS rule: %v", err)
	}

	tcpMssRule = []string{
		"-i", srv.Ifname(),
		"-p", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment", "--comment", fmt.Sprintf("vprox TCP MSS inbound rule for %s", srv.Ifname()),
	}
	if err := srv.Ipt.Delete("mangle", "FORWARD", tcpMssRule...); err != nil {
		log.Printf("failed to remove inbound TCP MSS rule: %v", err)
	}

	if err := srv.iptablesIpipMssRules(false); err != nil {
		log.Printf("failed to remove ipip MSS rules: %v", err)
	}

	if srv.Region == "us-west" {
		// Remove SNAT rule for internal traffic
		rule = []string{
			"-s", srv.WgCidr.String(),
			"-d", srv.InternalNetworkCidr,
			"-o", srv.InternalBindIface.Attrs().Name,
			"-j", "SNAT", "--to-source", srv.BindAddr.String(),
			"-m", "comment", "--comment", "SNAT for WireGuard to internal network",
		}
		if err := srv.Ipt.Delete("nat", "POSTROUTING", rule...); err != nil {
			log.Printf("failed to remove SNAT rule for internal traffic: %v", err)
		}

		// Remove forward rule from WireGuard to internal network
		rule = []string{
			"-i", srv.Ifname(),
			"-o", srv.InternalBindIface.Attrs().Name,
			"-s", srv.WgCidr.String(),
			"-d", srv.InternalNetworkCidr,
			"-j", "ACCEPT",
			"-m", "comment", "--comment", "Forward from WireGuard to internal network",
		}
		if err := srv.Ipt.Delete("filter", "FORWARD", rule...); err != nil {
			log.Printf("failed to remove forward rule from WireGuard to internal network: %v", err)
		}

		// Remove forward rule from internal network to WireGuard
		rule = []string{
			"-i", srv.InternalBindIface.Attrs().Name,
			"-o", srv.Ifname(),
			"-s", srv.InternalNetworkCidr,
			"-d", srv.WgCidr.String(),
			"-j", "ACCEPT",
			"-m", "comment", "--comment", "Forward from internal network to WireGuard",
		}
		if err := srv.Ipt.Delete("filter", "FORWARD", rule...); err != nil {
			log.Printf("failed to remove forward rule from internal network to WireGuard: %v", err)
		}
	}
}

func (srv *Server) removeIdlePeersLoop() {
	for {
		// Wait for up to 5 seconds, or stop when the context is done.
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}

		if err := srv.removeIdlePeers(); err != nil {
			log.Printf("error removing idle peers: %v", err)
		}
	}
}

func (srv *Server) removeIdlePeers() error {
	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device: %v", err)
	}

	// Hold the lock for access to newPeers.
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// Clean up old entries from newPeers map, which should have connected by now.
	for key, creationTime := range srv.newPeers {
		if time.Since(creationTime) > PeerIdleTimeout {
			delete(srv.newPeers, key)
		}
	}

	var removePeers []wgtypes.PeerConfig
	var removeIps []netip.Addr
	var removeKeys []wgtypes.Key
	for _, peer := range device.Peers {
		lastConnect, hasConnected := srv.newPeers[peer.PublicKey]
		var idle bool
		if peer.LastHandshakeTime.IsZero() {
			idle = !hasConnected
		} else {
			// A stale handshake alone isn't enough to reap: a recent /connect
			// (refreshed under srv.mu before the handler's device write) means
			// the peer is reconnecting or has a request in flight, and reaping
			// it would free an IP the handler is handing out, desyncing
			// peerIPs/ipAllocator from the device.
			idle = time.Since(peer.LastHandshakeTime) > PeerIdleTimeout &&
				time.Since(lastConnect) > ConnectGracePeriod
		}

		if idle {
			if len(peer.AllowedIPs) > 0 {
				ipv4 := peer.AllowedIPs[0].IP.To4()
				if ipv4 != nil {
					log.Printf("[%v] removing idle peer at %v: %v",
						srv.BindAddr, ipv4, peer.PublicKey)
					removeIps = append(removeIps, netip.AddrFrom4([4]byte(ipv4)))
				}
			}
			removePeers = append(removePeers, wgtypes.PeerConfig{
				PublicKey: peer.PublicKey,
				Remove:    true,
			})
			removeKeys = append(removeKeys, peer.PublicKey)
		}
	}

	if len(removePeers) > 0 {
		err := srv.WgClient.ConfigureDevice(srv.Ifname(), wgtypes.Config{Peers: removePeers})
		if err != nil {
			return err
		}
		for _, ip := range removeIps {
			srv.ipAllocator.Free(ip)
		}
		// Drop in-memory index entries so future reconnects from these peers
		// allocate fresh IPs and stay consistent with the device and allocator.
		for _, key := range removeKeys {
			delete(srv.peerIPs, key)
		}
	}

	return nil
}

func (srv *Server) addBindAddrLoop() {
	for {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		_ = srv.addBindAddr()
	}
}

func (srv *Server) addBindAddr() error {
	// Add the bind address to the host's network interface.
	ipnet := prefixToIPNet(netip.PrefixFrom(srv.BindAddr, 32))
	return netlink.AddrReplace(srv.BindIface, &netlink.Addr{
		IPNet:       &ipnet,
		ValidLft:    60, // expiry time in seconds
		PreferedLft: 60, // expiry time in seconds
	})
}

func (srv *Server) ListenForHttps() error {
	if !srv.BindAddr.Is4() {
		return fmt.Errorf("invalid IPv4 bind address: %v", srv.BindAddr)
	}

	go srv.removeIdlePeersLoop()
	go srv.removeIdleIpipPeersLoop()

	// Some bind addresses may not have been added to the network interface. If
	// that is the case, we need to add it (transiently).
	_ = srv.addBindAddr()
	go srv.addBindAddrLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.indexHandler)
	mux.HandleFunc("/connect", srv.connectHandler)
	mux.HandleFunc("/connect-ipip", srv.connectIpipHandler)

	cert, err := loadServerTls()
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:443", srv.BindAddr))
	if err != nil {
		return fmt.Errorf("failed to listen on :443: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %v:443\n", srv.BindAddr)
		err = httpServer.ServeTLS(listener, "", "")
		if err != http.ErrServerClosed {
			errCh <- fmt.Errorf("https server failed to serve %v: %v", srv.BindAddr, err)
		} else {
			errCh <- nil
		}
	}()

	select {
	case <-srv.Ctx.Done():
		log.Printf("server no longer listening on %v:443\n", srv.BindAddr)
		return httpServer.Shutdown(srv.Ctx)
	case err = <-errCh:
		return err
	}
}

//go:embed certs/cert.pem certs/key.pem
var defaultCerts embed.FS

// loadServerTls loads the server's TLS certificate for control connections.
func loadServerTls() (tls.Certificate, error) {
	certData, _ := defaultCerts.ReadFile("certs/cert.pem")
	keyData, _ := defaultCerts.ReadFile("certs/key.pem")

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load server certificate: %v", err)
	}
	return cert, nil
}
