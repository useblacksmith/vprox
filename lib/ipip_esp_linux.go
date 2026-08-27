//go:build linux

package lib

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
)

// ipProtoIpip is the IP protocol number for IP-in-IP (used as an xfrm
// selector protocol, distinct from the xfrm SA protocol which is ESP).
const ipProtoIpip = 4

// ipipEspMtu is the MTU set on an IPIP interface once its outer path is
// ESP-wrapped. Transport-mode AES-CBC ESP adds up to ~57 bytes (8 ESP
// header + 16 IV + pad-to-16 + 2 trailer + 16 ICV) on top of the 20-byte
// IPIP outer header, so the default 1480 no longer fits in a 1500-byte
// physical MTU; worst case at 1424 is 1424 + 6 pad + 20 + 56 = 1492. The
// wildcard --clamp-mss-to-pmtu MSS rules pick this up automatically.
const ipipEspMtu = 1424

// ipipEspXfrmState builds one transport-mode ESP xfrm state.
func ipipEspXfrmState(src, dst netip.Addr, sa ipipEspSA) *netlink.XfrmState {
	return &netlink.XfrmState{
		Src:          addrToIp(src),
		Dst:          addrToIp(dst),
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TRANSPORT,
		Spi:          int(sa.Spi),
		ReplayWindow: 32,
		Crypt: &netlink.XfrmStateAlgo{
			Name: "cbc(aes)",
			Key:  sa.EncKey,
		},
		Auth: &netlink.XfrmStateAlgo{
			Name: "hmac(sha256)",
			Key:  sa.AuthKey,
			// RFC 4868 truncation, matching macOS xnu. Linux's legacy
			// default for hmac(sha256) is 96 bits, which does NOT
			// interop, so this must be explicit.
			TruncateLen: ipipEspICVBits,
		},
	}
}

// ipipEspStates returns the two transport-mode SAs for a client pair, in
// (to-server, to-client) order.
func (srv *Server) ipipEspStates(clientIP netip.Addr, keys ipipEspKeys) (toServer, toClient *netlink.XfrmState) {
	toServer = ipipEspXfrmState(clientIP, srv.BindAddr, keys.ToServer)
	toClient = ipipEspXfrmState(srv.BindAddr, clientIP, keys.ToClient)
	return toServer, toClient
}

// ipipEspPolicies returns the require-ESP policies for the proto-4 traffic
// between srv.BindAddr and clientIP, in (in, out) order. The selector is
// scoped to IP proto 4 between exactly the two hosts: the HTTPS control
// channel (TCP 443) between the same pair must stay reachable without ESP,
// otherwise a client could never re-key. A non-optional template means
// plaintext IPIP matching the selector is dropped, not passed through.
func (srv *Server) ipipEspPolicies(clientIP netip.Addr) (in, out *netlink.XfrmPolicy) {
	server := addrToIp(srv.BindAddr)
	client := addrToIp(clientIP)
	serverNet := prefixToIPNet(netip.PrefixFrom(srv.BindAddr, 32))
	clientNet := prefixToIPNet(netip.PrefixFrom(clientIP, 32))
	in = &netlink.XfrmPolicy{
		Src:   &clientNet,
		Dst:   &serverNet,
		Proto: ipProtoIpip,
		Dir:   netlink.XFRM_DIR_IN,
		Tmpls: []netlink.XfrmPolicyTmpl{{
			Src:   client,
			Dst:   server,
			Proto: netlink.XFRM_PROTO_ESP,
			Mode:  netlink.XFRM_MODE_TRANSPORT,
		}},
	}
	out = &netlink.XfrmPolicy{
		Src:   &serverNet,
		Dst:   &clientNet,
		Proto: ipProtoIpip,
		Dir:   netlink.XFRM_DIR_OUT,
		Tmpls: []netlink.XfrmPolicyTmpl{{
			Src:   server,
			Dst:   client,
			Proto: netlink.XFRM_PROTO_ESP,
			Mode:  netlink.XFRM_MODE_TRANSPORT,
		}},
	}
	return in, out
}

// installIpipEsp installs the freshly minted SA pair and require-ESP
// policies for clientIP, replacing any previous SAs for the pair (a repeated
// /connect-ipip with esp re-mints; old SPIs are deleted first so the kernel
// holds exactly one SA per direction). It also drops the tunnel MTU to fit
// the ESP overhead. On failure the partially installed state is removed
// best-effort so the pair is either fully protected or clean.
func (srv *Server) installIpipEsp(clientIP netip.Addr, ifname string, keys ipipEspKeys) error {
	if err := srv.deleteIpipEspStates(clientIP); err != nil {
		return fmt.Errorf("delete stale esp states: %v", err)
	}

	toServer, toClient := srv.ipipEspStates(clientIP, keys)
	polIn, polOut := srv.ipipEspPolicies(clientIP)

	install := func() error {
		if err := netlink.XfrmStateAdd(toServer); err != nil {
			return fmt.Errorf("add to-server esp state: %v", err)
		}
		if err := netlink.XfrmStateAdd(toClient); err != nil {
			return fmt.Errorf("add to-client esp state: %v", err)
		}
		// Update is an upsert: adopted pairs may already have policies
		// from a previous vprox process.
		if err := netlink.XfrmPolicyUpdate(polIn); err != nil {
			return fmt.Errorf("install inbound esp policy: %v", err)
		}
		if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
			return fmt.Errorf("install outbound esp policy: %v", err)
		}
		return nil
	}
	if err := install(); err != nil {
		if cleanupErr := srv.removeIpipEsp(clientIP); cleanupErr != nil {
			log.Printf("[%v] failed to clean up partial esp install for %v: %v",
				srv.BindAddr, clientIP, cleanupErr)
		}
		return err
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("lookup %s for esp mtu: %v", ifname, err)
	}
	if err := netlink.LinkSetMTU(link, ipipEspMtu); err != nil {
		return fmt.Errorf("set %s mtu %d: %v", ifname, ipipEspMtu, err)
	}
	return nil
}

// removeIpipEsp removes the pair's require-ESP policies and every ESP SA
// between srv.BindAddr and clientIP. Missing objects are not an error, so
// this is safe to call for peers that never had ESP (plaintext requests and
// teardown call it unconditionally).
func (srv *Server) removeIpipEsp(clientIP netip.Addr) error {
	polIn, polOut := srv.ipipEspPolicies(clientIP)
	var errs []error
	for _, pol := range []*netlink.XfrmPolicy{polIn, polOut} {
		if err := netlink.XfrmPolicyDel(pol); err != nil && !xfrmNotFound(err) {
			errs = append(errs, fmt.Errorf("delete %v esp policy: %v", pol.Dir, err))
		}
	}
	if err := srv.deleteIpipEspStates(clientIP); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// deleteIpipEspStates deletes every ESP SA between srv.BindAddr and
// clientIP, in either direction. SPIs are not required: after a restart the
// process does not know the SPIs of adopted pairs, so deletion is keyed on
// the address pair.
func (srv *Server) deleteIpipEspStates(clientIP netip.Addr) error {
	states, err := netlink.XfrmStateList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("list esp states: %v", err)
	}
	server := addrToIp(srv.BindAddr)
	client := addrToIp(clientIP)
	var errs []error
	for i := range states {
		s := &states[i]
		if s.Proto != netlink.XFRM_PROTO_ESP {
			continue
		}
		match := (s.Src.Equal(client) && s.Dst.Equal(server)) ||
			(s.Src.Equal(server) && s.Dst.Equal(client))
		if !match {
			continue
		}
		if err := netlink.XfrmStateDel(s); err != nil && !xfrmNotFound(err) {
			errs = append(errs, fmt.Errorf("delete esp state spi 0x%x: %v", s.Spi, err))
			continue
		}
		log.Printf("[%v] deleted esp state for %v (spi 0x%x)",
			srv.BindAddr, clientIP, s.Spi)
	}
	return errors.Join(errs...)
}

// xfrmNotFound reports the kernel's "no such object" answers to xfrm
// delete/get requests.
func xfrmNotFound(err error) bool {
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.ENOENT)
}
