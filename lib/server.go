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

	mu       sync.Mutex // Protects the fields below.
	newPeers map[wgtypes.Key]time.Time
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

	// If the new connection already exists as a peer, just return that IP.
	peerIp := netip.AddrFrom4([4]byte{})

	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		http.Error(w, "failed to get WireGuard device", http.StatusInternalServerError)
	}
	for _, peer := range device.Peers {
		if peer.PublicKey == peerKey && len(peer.AllowedIPs) > 0 {
			peerIp, _ = netip.AddrFromSlice([]byte(peer.AllowedIPs[0].IP.To4()))
			break
		}
	}

	// Add a WireGuard peer for the new connection.
	if peerIp.IsUnspecified() {
		peerIp = srv.ipAllocator.Allocate()
	}
	if peerIp.IsUnspecified() {
		log.Printf("no more ip addresses available in %v", srv.WgCidr)
		http.Error(w, "no more IP addresses available", http.StatusServiceUnavailable)
		return
	}

	srv.mu.Lock()
	srv.newPeers[peerKey] = time.Now()
	srv.mu.Unlock()

	clientIp := strings.Split(r.RemoteAddr, ":")[0] // for logging
	log.Printf("[%v] new peer %v at %v: %v", srv.BindAddr, clientIp, peerIp, peerKey)
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
		srv.ipAllocator.Free(peerIp)
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

func (srv *Server) StartWireguard() error {
	ifname := srv.Ifname()
	link := &linkWireguard{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
	_ = netlink.LinkDel(link) // remove if it already exists
	err := netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to create WireGuard device: %v", err)
	}

	ipnet := prefixToIPNet(srv.WgCidr)
	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: &ipnet})
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to add address to WireGuard device: %v", err)
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		netlink.LinkDel(link)
		return fmt.Errorf("failed to bring up WireGuard device: %v", err)
	}

	listenPort := WireguardListenPortBase + int(srv.Index)
	err = srv.WgClient.ConfigureDevice(ifname, wgtypes.Config{
		PrivateKey: &srv.Key,
		ListenPort: &listenPort,
	})
	if err != nil {
		netlink.LinkDel(link)
		return err
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

	// SNAT rule for internal network traffic. This is currently only applicable for boxes in
	// the US.
	if srv.Region == "us-west" {
		rule = []string{
			"-s", srv.WgCidr.String(),
			"-d", srv.InternalNetworkCidr,
			"-o", srv.InternalBindIface.Attrs().Name,
			"-j", "SNAT", "--to-source", srv.BindAddr.String(),
			"-m", "comment", "--comment", "SNAT for WireGuard to internal network",
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
	for _, peer := range device.Peers {
		var idle bool
		if peer.LastHandshakeTime.IsZero() {
			_, isNew := srv.newPeers[peer.PublicKey]
			idle = !isNew
		} else {
			idle = time.Since(peer.LastHandshakeTime) > PeerIdleTimeout
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

	// Some bind addresses may not have been added to the network interface. If
	// that is the case, we need to add it (transiently).
	_ = srv.addBindAddr()
	go srv.addBindAddrLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.indexHandler)
	mux.HandleFunc("/connect", srv.connectHandler)

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
