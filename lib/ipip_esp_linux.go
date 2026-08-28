//go:build linux

package lib

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"syscall"
	"time"

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

	// The SAs and require-ESP policies are now live in the kernel. Any
	// failure past this point must unwind them: the handler returns an
	// error to the client, so the client never receives the minted keys,
	// and a pair left require-ESP'd without a key holder is a blackhole
	// until a successful retry (see ipipEspFinishInstall).
	err, unwindErr := ipipEspFinishInstall(
		func() error {
			link, err := netlink.LinkByName(ifname)
			if err != nil {
				return fmt.Errorf("lookup %s for esp mtu: %v", ifname, err)
			}
			if err := netlink.LinkSetMTU(link, ipipEspMtu); err != nil {
				return fmt.Errorf("set %s mtu %d: %v", ifname, ipipEspMtu, err)
			}
			return nil
		},
		func() error { return srv.removeIpipEsp(clientIP) },
	)
	if err != nil {
		if unwindErr != nil {
			log.Printf("[%v] esp unwind after failed install for %v (%s) also FAILED: %v; pair may be left require-ESP'd",
				srv.BindAddr, clientIP, ifname, unwindErr)
		} else {
			log.Printf("[%v] esp install unwound for %v (%s) after post-install failure: %v",
				srv.BindAddr, clientIP, ifname, err)
		}
		return err
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

// Rekey timing. The switch poll watches the new inbound SA for its first
// packet -- the client installs and starts using the new generation within
// its own rekey step (seconds), so 60s of 500ms polls is generous. The GC
// grace lets in-flight packets on the old generation drain (and gives the
// client time to finish its own switch bookkeeping) before old states are
// deleted.
const (
	ipipEspSwitchPoll    = 500 * time.Millisecond
	ipipEspSwitchTimeout = 60 * time.Second
	ipipEspGcGrace       = 2 * time.Minute
)

// rekeyIpipEsp rotates the pair's SA generation. Caller must hold ipipMu
// and have minted keys (and bumped p.espRekeyEpoch). It installs only the
// new INBOUND (client->server) SA next to the existing generation(s) and
// re-asserts the require-ESP policies; the outbound switch happens in a
// background poll once the client demonstrably transmits on the new
// generation (see ipipEspSwitchLoop). The pair therefore always has a
// working generation in both directions: old outbound keeps flowing until
// the new inbound proves live.
//
// If the pair has no live outbound SA (fresh connect that asked for rekey,
// or state lost some other way), this falls back to the destructive full
// install -- there is nothing to hand over from.
func (srv *Server) rekeyIpipEsp(p *ipipPeer, keys ipipEspKeys) error {
	states, err := srv.listIpipEspStateKeys()
	if err != nil {
		return fmt.Errorf("list esp states for rekey: %v", err)
	}
	live := false
	for _, s := range states {
		if s.Src == srv.BindAddr && s.Dst == p.clientIP {
			live = true
			break
		}
	}
	if !live {
		log.Printf("[%v] esp rekey requested for %v (%s) without live SAs; performing full install",
			srv.BindAddr, p.clientIP, p.ifname)
		if err := srv.installIpipEsp(p.clientIP, p.ifname, keys); err != nil {
			return err
		}
		p.espSpiToServer, p.espSpiToClient = keys.ToServer.Spi, keys.ToClient.Spi
		p.espPrevSpiToServer, p.espPrevSpiToClient = 0, 0
		return nil
	}

	// The generation to protect from this rekey's GC: the newest existing
	// inbound, i.e. what the client's outbound rolls back to if its
	// health check fails. Chosen from the kernel (AddTime) rather than
	// in-memory SPIs so restart-adopted pairs are protected too.
	prevInbound := newestIpipEspInboundSpi(states, p.clientIP, srv.BindAddr, keys.ToServer.Spi)

	toServer, _ := srv.ipipEspStates(p.clientIP, keys)
	if err := netlink.XfrmStateAdd(toServer); err != nil {
		return fmt.Errorf("add rekey to-server esp state: %v", err)
	}
	// Re-assert the require-ESP policies (upsert). They are SPI-agnostic,
	// but an adopted pair whose policies were somehow lost gets healed here.
	polIn, polOut := srv.ipipEspPolicies(p.clientIP)
	if err := netlink.XfrmPolicyUpdate(polIn); err != nil {
		return fmt.Errorf("re-assert inbound esp policy: %v", err)
	}
	if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
		return fmt.Errorf("re-assert outbound esp policy: %v", err)
	}

	p.espPrevSpiToServer, p.espPrevSpiToClient = prevInbound, p.espSpiToClient
	p.espSpiToServer, p.espSpiToClient = keys.ToServer.Spi, keys.ToClient.Spi
	pending := keys.ToClient
	p.espPendingToClient = &pending

	log.Printf("[%v] esp rekey minted for ipip peer %v (%s, new spi to-server 0x%x, to-client 0x%x, prev to-server 0x%x, to-client 0x%x)",
		srv.BindAddr, p.clientIP, p.ifname,
		keys.ToServer.Spi, keys.ToClient.Spi,
		p.espPrevSpiToServer, p.espPrevSpiToClient)

	go srv.ipipEspSwitchLoop(p.clientIP, p.espRekeyEpoch, keys.ToServer.Spi)
	return nil
}

// ipipEspSwitchLoop waits for the client's first packet on the new inbound
// SA (proof the client transmits on the new generation), then switches the
// server's outbound to it. On timeout it switches anyway -- the client
// keeps every inbound generation it knows (including a rolled-back one),
// so a timeout-switch stays decryptable; only a client that vanished
// mid-rekey would miss the new generation, and its next connect replaces
// everything.
func (srv *Server) ipipEspSwitchLoop(clientIP netip.Addr, epoch uint64, newSpiToServer uint32) {
	lookup := &netlink.XfrmState{
		Src:   addrToIp(clientIP),
		Dst:   addrToIp(srv.BindAddr),
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(newSpiToServer),
	}
	deadline := time.Now().Add(ipipEspSwitchTimeout)
	byCounter := false
	for time.Now().Before(deadline) {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(ipipEspSwitchPoll):
		}
		state, err := netlink.XfrmStateGet(lookup)
		if err != nil {
			if xfrmNotFound(err) {
				log.Printf("[%v] esp rekey switch aborted for %v: new inbound state (spi 0x%x) gone",
					srv.BindAddr, clientIP, newSpiToServer)
				return
			}
			log.Printf("[%v] esp rekey switch poll failed transiently for %v: %v",
				srv.BindAddr, clientIP, err)
			continue
		}
		if state.Statistics.Packets > 0 {
			byCounter = true
			break
		}
	}
	srv.switchIpipEspOutbound(clientIP, epoch, byCounter)
}

// switchIpipEspOutbound installs the pending outbound SA and deletes every
// other server->client state so the kernel deterministically emits the new
// generation. After a counter-confirmed switch it schedules old-generation
// GC; after a timeout-switch it does NOT -- the client may have rolled
// back its outbound to the previous generation (health-check failure), and
// GC'ing that generation's inbound SA here would cut it off. The next
// confirmed rekey's GC sweeps all stale generations anyway.
func (srv *Server) switchIpipEspOutbound(clientIP netip.Addr, epoch uint64, byCounter bool) {
	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	p, ok := srv.ipipPeers[clientIP]
	if !ok || p.espRekeyEpoch != epoch || p.espPendingToClient == nil {
		log.Printf("[%v] esp rekey switch superseded for %v; not switching",
			srv.BindAddr, clientIP)
		return
	}
	sa := *p.espPendingToClient

	toClient := ipipEspXfrmState(srv.BindAddr, clientIP, sa)
	if err := netlink.XfrmStateAdd(toClient); err != nil {
		// Old outbound stays in place; the pair keeps flowing on the old
		// generation and the next rekey retries the whole rotation.
		log.Printf("[%v] esp rekey switch FAILED for %v: add to-client state (spi 0x%x): %v; keeping old outbound",
			srv.BindAddr, clientIP, sa.Spi, err)
		return
	}
	p.espPendingToClient = nil

	deleted, err := srv.deleteIpipEspStatesExcept(
		srv.BindAddr, clientIP, map[uint32]struct{}{sa.Spi: {}})
	if err != nil {
		log.Printf("[%v] esp rekey switch: old outbound delete FAILED for %v: %v",
			srv.BindAddr, clientIP, err)
		return
	}

	how := "timeout"
	if byCounter {
		how = "counter"
	}
	log.Printf("[%v] esp outbound switched for %v (spi to-client 0x%x, by %s, removed %d old outbound state(s))",
		srv.BindAddr, clientIP, sa.Spi, how, len(deleted))

	if byCounter {
		go srv.ipipEspGcLoop(clientIP, epoch)
	} else {
		log.Printf("[%v] esp rekey switch by timeout for %v: skipping old-generation GC (client may have rolled back); next confirmed rekey will sweep",
			srv.BindAddr, clientIP)
	}
}

// ipipEspGcLoop deletes every ESP state for the pair except the current
// generation, a grace period after a counter-confirmed switch. List-based
// deletion also sweeps generations vprox no longer knows about (map lost
// across a restart).
func (srv *Server) ipipEspGcLoop(clientIP netip.Addr, epoch uint64) {
	select {
	case <-srv.Ctx.Done():
		return
	case <-time.After(ipipEspGcGrace):
	}

	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	p, ok := srv.ipipPeers[clientIP]
	if !ok || p.espRekeyEpoch != epoch {
		log.Printf("[%v] esp rekey GC superseded for %v; skipping", srv.BindAddr, clientIP)
		return
	}
	keep := map[uint32]struct{}{
		p.espSpiToServer: {},
		p.espSpiToClient: {},
	}
	// Keep the previous inbound generation: a counter-confirmed switch
	// only proves the client transmitted on the new generation once (its
	// health check does that even when it fails), not that it stayed
	// there. If the client rolled back, its outbound is on this
	// generation, and "vprox keeps accepting both" is the rollback
	// contract. It is swept by the NEXT confirmed rekey's GC.
	if p.espPrevSpiToServer != 0 {
		keep[p.espPrevSpiToServer] = struct{}{}
	}
	var deleted []ipipEspStateKey
	for _, dir := range [][2]netip.Addr{
		{clientIP, srv.BindAddr},
		{srv.BindAddr, clientIP},
	} {
		d, err := srv.deleteIpipEspStatesExcept(dir[0], dir[1], keep)
		if err != nil {
			log.Printf("[%v] esp rekey GC FAILED for %v (%v->%v): %v",
				srv.BindAddr, clientIP, dir[0], dir[1], err)
			return
		}
		deleted = append(deleted, d...)
	}
	for _, s := range deleted {
		log.Printf("[%v] esp rekey GC'd old generation state for %v (spi 0x%x, %v->%v)",
			srv.BindAddr, clientIP, s.Spi, s.Src, s.Dst)
	}
	if len(deleted) == 0 {
		log.Printf("[%v] esp rekey GC for %v: nothing to sweep", srv.BindAddr, clientIP)
	}
}

// listIpipEspStateKeys lists all v4 ESP states as pure state keys.
func (srv *Server) listIpipEspStateKeys() ([]ipipEspStateKey, error) {
	states, err := netlink.XfrmStateList(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list esp states: %v", err)
	}
	keys := make([]ipipEspStateKey, 0, len(states))
	for i := range states {
		s := &states[i]
		if s.Proto != netlink.XFRM_PROTO_ESP {
			continue
		}
		src, srcOk := ipToAddr(s.Src)
		dst, dstOk := ipToAddr(s.Dst)
		if !srcOk || !dstOk {
			continue
		}
		keys = append(keys, ipipEspStateKey{
			Src:     src,
			Dst:     dst,
			Spi:     uint32(s.Spi),
			AddTime: s.Statistics.AddTime,
		})
	}
	return keys, nil
}

// deleteIpipEspStatesExcept deletes every ESP state flowing src->dst whose
// SPI is not in keep, returning the deleted keys. Missing states (raced by
// another deleter) are not errors.
func (srv *Server) deleteIpipEspStatesExcept(src, dst netip.Addr, keep map[uint32]struct{}) ([]ipipEspStateKey, error) {
	states, err := srv.listIpipEspStateKeys()
	if err != nil {
		return nil, err
	}
	victims := ipipEspStatesToDelete(states, src, dst, keep)
	var deleted []ipipEspStateKey
	var errs []error
	for _, v := range victims {
		st := &netlink.XfrmState{
			Src:   addrToIp(v.Src),
			Dst:   addrToIp(v.Dst),
			Proto: netlink.XFRM_PROTO_ESP,
			Spi:   int(v.Spi),
		}
		if err := netlink.XfrmStateDel(st); err != nil && !xfrmNotFound(err) {
			errs = append(errs, fmt.Errorf("delete esp state spi 0x%x: %v", v.Spi, err))
			continue
		}
		deleted = append(deleted, v)
	}
	return deleted, errors.Join(errs...)
}

// ipToAddr converts a net.IP to an IPv4 netip.Addr.
func ipToAddr(ip net.IP) (netip.Addr, bool) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(ipv4)), true
}
