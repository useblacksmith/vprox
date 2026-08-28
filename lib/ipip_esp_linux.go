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

// ipipEspReqid returns the xfrm reqid for a generation, derived from its
// SpiToClient. reqids exist to make OUTBOUND state selection deterministic
// and reversible: the out-policy template selects states by EXACT reqid
// match (verified on staging: a tmpl reqid never matches a state with a
// different reqid, including 0), so multiple outbound generations coexist
// and a policy update flips emission between them without deleting
// anything -- and without resetting sequence counters, which makes the
// flip replay-safe. Deriving the reqid from the SPI (instead of a counter)
// keeps it recoverable after a vprox restart from kernel state alone.
//
// Inbound states and the in-policy template always use reqid 0: inbound
// policy checks also require an exact reqid match between the decrypting
// SA and the template, and the whole point of the rotation protocol is
// that EVERY installed inbound generation stays acceptable at once.
func ipipEspReqid(spiToClient uint32) int {
	return int(spiToClient)
}

// ipipEspXfrmState builds one transport-mode ESP xfrm state.
func ipipEspXfrmState(src, dst netip.Addr, sa ipipEspSA, reqid int) *netlink.XfrmState {
	return &netlink.XfrmState{
		Src:          addrToIp(src),
		Dst:          addrToIp(dst),
		Proto:        netlink.XFRM_PROTO_ESP,
		Mode:         netlink.XFRM_MODE_TRANSPORT,
		Spi:          int(sa.Spi),
		Reqid:        reqid,
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
// (to-server, to-client) order. The to-client (outbound) state carries the
// generation's reqid; the to-server (inbound) state carries reqid 0 like
// every inbound generation (see ipipEspReqid).
func (srv *Server) ipipEspStates(clientIP netip.Addr, keys ipipEspKeys) (toServer, toClient *netlink.XfrmState) {
	toServer = ipipEspXfrmState(clientIP, srv.BindAddr, keys.ToServer, 0)
	toClient = ipipEspXfrmState(srv.BindAddr, clientIP, keys.ToClient, ipipEspReqid(keys.ToClient.Spi))
	return toServer, toClient
}

// ipipEspPolicies returns the require-ESP policies for the proto-4 traffic
// between srv.BindAddr and clientIP, in (in, out) order. The selector is
// scoped to IP proto 4 between exactly the two hosts: the HTTPS control
// channel (TCP 443) between the same pair must stay reachable without ESP,
// otherwise a client could never re-key. A non-optional template means
// plaintext IPIP matching the selector is dropped, not passed through.
//
// outReqid pins which outbound generation the kernel emits (see
// ipipEspReqid); the in policy always uses reqid 0 so every installed
// inbound generation is accepted.
func (srv *Server) ipipEspPolicies(clientIP netip.Addr, outReqid int) (in, out *netlink.XfrmPolicy) {
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
			Reqid: outReqid,
		}},
	}
	return in, out
}

// outboundIpipEspPolicyReqid reads the pair's outbound require-ESP policy
// from the kernel and returns its template reqid. found is false when the
// policy does not exist.
func (srv *Server) outboundIpipEspPolicyReqid(clientIP netip.Addr) (reqid int, found bool, err error) {
	_, out := srv.ipipEspPolicies(clientIP, 0)
	pol, err := netlink.XfrmPolicyGet(out)
	if err != nil {
		if xfrmNotFound(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("get outbound esp policy: %v", err)
	}
	if len(pol.Tmpls) == 0 {
		return 0, true, nil
	}
	return pol.Tmpls[0].Reqid, true, nil
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
	polIn, polOut := srv.ipipEspPolicies(clientIP, ipipEspReqid(keys.ToClient.Spi))

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
// this is safe to call for peers that never had ESP installed (teardown
// and restore call it unconditionally). Policy deletion is keyed by selector
// and direction, so the template reqid passed here is irrelevant.
func (srv *Server) removeIpipEsp(clientIP netip.Addr) error {
	polIn, polOut := srv.ipipEspPolicies(clientIP, 0)
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

// Rekey timing. The activation gate poll watches the newly activated
// generation's inbound SA for its first packet -- the client switches its
// outbound and health-checks within seconds of ACTIVATE, so the ~2 minute
// gate is generous. A packet within the gate is the on-the-wire proof
// that arms the counter-gated GC; gate EXPIRY means the client never
// completed its switch (and its ABANDON, if it sent one, was lost), so
// the activation is auto-reverted: the outbound policy flips back to the
// previous generation's reqid (replay-safe -- the old state was never
// deleted and its sequence counter kept counting). Old states are still
// never deleted on expiry. The GC grace lets in-flight packets on the old
// generation drain before old states are deleted after a PROVEN
// activation. The pending reap deletes a PREPAREd generation the client
// never activated or abandoned (helper died mid-protocol); it fires well
// after any legitimate in-protocol gap, and only if no other request
// touched the pair since.
const (
	ipipEspGcGatePoll     = 500 * time.Millisecond
	ipipEspActivationGate = 2 * time.Minute
	ipipEspGcGrace        = 2 * time.Minute
	ipipEspPendingReap    = 5 * time.Minute
)

// prepareIpipEspRekey is the PREPARE step of the forward-only rotation.
// Caller must hold ipipMu and have minted keys (and re-assigned
// p.espRekeyEpoch). It installs BOTH of the new generation's states -- the
// inbound next to every existing inbound, and the outbound under the
// generation's fresh reqid, which the (untouched) outbound policy does not
// select -- so nothing changes on the wire: the pair keeps flowing on the
// active generation in both directions. A later ACTIVATE flips emission.
//
// A previously prepared-but-never-activated generation is deleted first
// (its replacement is this call); a reap goroutine handles the case where
// no next PREPARE ever comes.
//
// If the pair has no live outbound SA (fresh connect that asked for rekey,
// or a rebooted box that lost kernel state), this falls back to the
// destructive full install and reports fresh=true -- there is nothing to
// hand over from, and the client must know its old generation is gone.
func (srv *Server) prepareIpipEspRekey(p *ipipPeer, keys ipipEspKeys) (fresh bool, err error) {
	states, err := srv.listIpipEspStateKeys()
	if err != nil {
		return false, fmt.Errorf("list esp states for rekey: %v", err)
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
			return false, err
		}
		p.setActiveEspGeneration(keys.ToServer.Spi, keys.ToClient.Spi)
		return true, nil
	}

	// Replace a stale pending generation: the client never activated or
	// abandoned it (e.g. its helper died between PREPARE and install), so
	// its states are dead weight the kernel should not accumulate.
	srv.dropPendingEspGenLocked(p, "replaced by new prepare")

	toServer, toClient := srv.ipipEspStates(p.clientIP, keys)
	if err := netlink.XfrmStateAdd(toServer); err != nil {
		return false, fmt.Errorf("add prepare to-server esp state: %v", err)
	}
	// Any failure past this point must unwind the orphan inbound (and the
	// outbound once it lands): the handler 500s, the client never
	// receives the keys, and unowned states would linger until a sweep.
	unwind := func(stage string, cause error) error {
		srv.deleteIpipEspStateBySpi(p.clientIP, srv.BindAddr, keys.ToServer.Spi)
		srv.deleteIpipEspStateBySpi(srv.BindAddr, p.clientIP, keys.ToClient.Spi)
		log.Printf("[%v] esp prepare unwound for %v after %s failure", srv.BindAddr, p.clientIP, stage)
		return cause
	}
	if err := netlink.XfrmStateAdd(toClient); err != nil {
		return false, unwind("outbound state add", fmt.Errorf("add prepare to-client esp state: %v", err))
	}

	// Re-assert the inbound policy (upsert; reqid-0 template accepts every
	// inbound generation). The OUTBOUND policy is deliberately left alone
	// -- it must keep selecting the active generation -- unless it is
	// missing entirely (lost somehow on an adopted pair), in which case it
	// is healed to point at the newest pre-existing outbound generation.
	polIn, _ := srv.ipipEspPolicies(p.clientIP, 0)
	if err := netlink.XfrmPolicyUpdate(polIn); err != nil {
		return false, unwind("inbound policy", fmt.Errorf("re-assert inbound esp policy: %v", err))
	}
	_, outFound, err := srv.outboundIpipEspPolicyReqid(p.clientIP)
	if err != nil {
		return false, unwind("outbound policy read", err)
	}
	if !outFound {
		healReqid, ok := newestIpipEspToClientReqid(states, srv.BindAddr, p.clientIP, keys.ToClient.Spi)
		if !ok {
			// live==true guarantees at least one server->client state.
			healReqid = 0
		}
		_, polOut := srv.ipipEspPolicies(p.clientIP, healReqid)
		if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
			return false, unwind("outbound policy heal", fmt.Errorf("heal outbound esp policy: %v", err))
		}
		log.Printf("[%v] esp outbound policy healed for %v (reqid 0x%x)",
			srv.BindAddr, p.clientIP, healReqid)
	}

	p.espPendingSpiToServer, p.espPendingSpiToClient = keys.ToServer.Spi, keys.ToClient.Spi

	log.Printf("[%v] esp generation prepared for ipip peer %v (%s, spi to-server 0x%x, to-client 0x%x, reqid 0x%x; policy untouched)",
		srv.BindAddr, p.clientIP, p.ifname,
		keys.ToServer.Spi, keys.ToClient.Spi, ipipEspReqid(keys.ToClient.Spi))

	go srv.ipipEspPendingReapLoop(p.clientIP, p.espRekeyEpoch,
		keys.ToServer.Spi, keys.ToClient.Spi)
	return false, nil
}

// dropPendingEspGenLocked deletes the peer's pending generation's kernel
// states (if any) and clears the pending bookkeeping. Caller must hold
// ipipMu. Never touches active or previous generations.
func (srv *Server) dropPendingEspGenLocked(p *ipipPeer, why string) {
	if p.espPendingSpiToServer == 0 && p.espPendingSpiToClient == 0 {
		return
	}
	log.Printf("[%v] esp pending generation dropped for %v (spi to-server 0x%x, to-client 0x%x): %s",
		srv.BindAddr, p.clientIP, p.espPendingSpiToServer, p.espPendingSpiToClient, why)
	srv.deleteIpipEspStateBySpi(p.clientIP, srv.BindAddr, p.espPendingSpiToServer)
	srv.deleteIpipEspStateBySpi(srv.BindAddr, p.clientIP, p.espPendingSpiToClient)
	p.espPendingSpiToServer, p.espPendingSpiToClient = 0, 0
}

// deleteIpipEspStateBySpi deletes exactly one ESP state by direction and
// SPI, tolerating missing state. spi 0 is a no-op.
func (srv *Server) deleteIpipEspStateBySpi(src, dst netip.Addr, spi uint32) {
	if spi == 0 {
		return
	}
	st := &netlink.XfrmState{
		Src:   addrToIp(src),
		Dst:   addrToIp(dst),
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(spi),
	}
	if err := netlink.XfrmStateDel(st); err != nil && !xfrmNotFound(err) {
		log.Printf("[%v] failed to delete esp state %v->%v spi 0x%x: %v",
			srv.BindAddr, src, dst, spi, err)
	}
}

// activateIpipEsp is the ACTIVATE step: flip the outbound policy template
// to the prepared generation's reqid. The previously emitting state is NOT
// deleted -- the flip is reversible (abandonIpipEsp) and replay-safe
// because Linux resumes a retained state's sequence counter. Idempotent by
// SpiToClient. Caller must hold ipipMu and have re-assigned the epoch.
func (srv *Server) activateIpipEsp(p *ipipPeer, spiToClient uint32) error {
	if p.espSpiToClient == spiToClient {
		log.Printf("[%v] esp activate for %v (spi to-client 0x%x): already active",
			srv.BindAddr, p.clientIP, spiToClient)
		return nil
	}

	// The generation must exist in the kernel (PREPAREd earlier -- by this
	// process or by one that restarted since; the kernel is the source of
	// truth, not the peer struct).
	if _, err := netlink.XfrmStateGet(&netlink.XfrmState{
		Src:   addrToIp(srv.BindAddr),
		Dst:   addrToIp(p.clientIP),
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(spiToClient),
	}); err != nil {
		if xfrmNotFound(err) {
			return fmt.Errorf("no prepared to-client state with spi 0x%x", spiToClient)
		}
		return fmt.Errorf("look up prepared to-client state 0x%x: %v", spiToClient, err)
	}

	prevReqid, prevFound, err := srv.outboundIpipEspPolicyReqid(p.clientIP)
	if err != nil {
		return err
	}

	_, polOut := srv.ipipEspPolicies(p.clientIP, ipipEspReqid(spiToClient))
	if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
		return fmt.Errorf("flip outbound esp policy to reqid 0x%x: %v", ipipEspReqid(spiToClient), err)
	}

	// Bookkeeping: the activated generation becomes active; what was
	// active becomes previous (still installed, still decrypting); the
	// pre-flip policy reqid is kept so an ABANDON can revert the flip.
	newToServer := uint32(0)
	if p.espPendingSpiToClient == spiToClient {
		newToServer = p.espPendingSpiToServer
	}
	p.espPrevSpiToServer, p.espPrevSpiToClient = p.espSpiToServer, p.espSpiToClient
	p.espPrevReqid, p.espPrevReqidValid = prevReqid, prevFound
	p.espSpiToServer, p.espSpiToClient = newToServer, spiToClient
	p.espPendingSpiToServer, p.espPendingSpiToClient = 0, 0

	log.Printf("[%v] esp generation activated for ipip peer %v (%s): outbound policy now reqid 0x%x (spi to-client 0x%x, to-server 0x%x); previous generation retained",
		srv.BindAddr, p.clientIP, p.ifname, ipipEspReqid(spiToClient), spiToClient, newToServer)

	// GC of superseded generations is gated on dataplane evidence: the
	// new inbound must carry packets (the client's post-switch health
	// check) before anything old is deleted. Without the to-server SPI
	// (activation after a vprox restart lost the pending bookkeeping)
	// there is no counter to gate on, so no GC -- the next successful
	// rotation sweeps instead.
	if newToServer != 0 {
		go srv.ipipEspGcGateLoop(p.clientIP, p.espRekeyEpoch, newToServer)
	} else {
		log.Printf("[%v] esp activate for %v: to-server SPI unknown (restart mid-protocol?); skipping counter-gated GC, next rotation sweeps",
			srv.BindAddr, p.clientIP)
	}
	return nil
}

// abandonIpipEsp is the ABANDON step, the client's escape hatch when its
// on-the-wire proof of the new generation failed.
//
//   - Abandoning a still-pending generation deletes its two (never
//     emitting, never proven) states and nothing else.
//   - Abandoning the ACTIVE generation flips the outbound policy back to
//     the pre-activation reqid -- replay-safe, since the previous state
//     was never deleted and its sequence counter kept counting -- and
//     restores the previous generation as active. The abandoned states
//     stay installed (the client may have partial state; deleting here
//     buys nothing) until a later successful rotation's GC sweeps them.
//   - Anything else is a stale/duplicate abandon and is a no-op.
//
// Caller must hold ipipMu and have re-assigned the epoch (which also
// cancels the abandoned generation's GC gate loop).
func (srv *Server) abandonIpipEsp(p *ipipPeer, spiToClient uint32) error {
	if p.espPendingSpiToClient == spiToClient && spiToClient != 0 {
		srv.dropPendingEspGenLocked(p, "abandoned by client before activation")
		return nil
	}
	if p.espSpiToClient == spiToClient && spiToClient != 0 {
		if !p.espPrevReqidValid {
			return fmt.Errorf("no pre-activation policy reqid recorded; cannot revert flip")
		}
		_, polOut := srv.ipipEspPolicies(p.clientIP, p.espPrevReqid)
		if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
			return fmt.Errorf("revert outbound esp policy to reqid 0x%x: %v", p.espPrevReqid, err)
		}
		log.Printf("[%v] esp generation 0x%x abandoned for ipip peer %v (%s): outbound policy reverted to reqid 0x%x; abandoned states left for next rotation's sweep",
			srv.BindAddr, spiToClient, p.clientIP, p.ifname, p.espPrevReqid)
		p.espSpiToServer, p.espSpiToClient = p.espPrevSpiToServer, p.espPrevSpiToClient
		p.espPrevSpiToServer, p.espPrevSpiToClient = 0, 0
		p.espPrevReqid, p.espPrevReqidValid = 0, false
		return nil
	}
	log.Printf("[%v] esp abandon for %v (spi to-client 0x%x): not pending or active; nothing to do",
		srv.BindAddr, p.clientIP, spiToClient)
	return nil
}

// ipipEspGcGateLoop is the counter gate after an ACTIVATE: it waits for
// the first packet on the newly active generation's INBOUND SA --
// on-the-wire proof the client completed its own switch -- then, after a
// grace period, sweeps every other state of the pair. On gate expiry it
// deletes NOTHING, but the activation was provisional: the outbound
// policy flip is auto-reverted to the previous generation (see
// autoRevertIpipEspActivation), because a client that never transmitted
// on the new generation either failed its own switch or lost its ABANDON,
// and leaving the pair emitting on an unproven generation strands it.
func (srv *Server) ipipEspGcGateLoop(clientIP netip.Addr, epoch uint64, newSpiToServer uint32) {
	lookup := &netlink.XfrmState{
		Src:   addrToIp(clientIP),
		Dst:   addrToIp(srv.BindAddr),
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(newSpiToServer),
	}
	deadline := time.Now().Add(ipipEspActivationGate)
	confirmed := false
	for time.Now().Before(deadline) {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(ipipEspGcGatePoll):
		}
		state, err := netlink.XfrmStateGet(lookup)
		if err != nil {
			if xfrmNotFound(err) {
				log.Printf("[%v] esp GC gate aborted for %v: new inbound state (spi 0x%x) gone",
					srv.BindAddr, clientIP, newSpiToServer)
				return
			}
			log.Printf("[%v] esp GC gate poll failed transiently for %v: %v",
				srv.BindAddr, clientIP, err)
			continue
		}
		if state.Statistics.Packets > 0 {
			confirmed = true
			break
		}
	}
	if !confirmed {
		srv.autoRevertIpipEspActivation(clientIP, epoch, newSpiToServer)
		return
	}

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
	// Epoch match means no request touched the pair since the ACTIVATE
	// that spawned this loop, so the active generation is still the one
	// the counter proved. Everything else -- previous generation,
	// abandoned strays, restart orphans -- is swept (list-based).
	keep := map[uint32]struct{}{
		p.espSpiToServer: {},
		p.espSpiToClient: {},
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
	p.espPrevSpiToServer, p.espPrevSpiToClient = 0, 0
	p.espPrevReqid, p.espPrevReqidValid = 0, false
	for _, s := range deleted {
		log.Printf("[%v] esp rekey GC'd old generation state for %v (spi 0x%x, %v->%v)",
			srv.BindAddr, clientIP, s.Spi, s.Src, s.Dst)
	}
	if len(deleted) == 0 {
		log.Printf("[%v] esp rekey GC for %v: nothing to sweep", srv.BindAddr, clientIP)
	}
}

// autoRevertIpipEspActivation walks back a PROVISIONAL activation whose
// gate expired without a single packet on the new generation's inbound
// SA: the outbound policy template flips back to the previous
// generation's reqid, exactly like a client ABANDON of the activated
// generation. Replay-safe -- the previous outbound state was never
// deleted, so Linux resumes its sequence counter. Nothing is deleted
// here; the unproven generation's states stay installed until a later
// successful rotation's sweep.
//
// This is what makes a LOST ABANDON harmless: a client whose proof failed
// walks away and retries with a fresh generation while still transmitting
// on the old one; without the revert, its abandon message was the only
// thing standing between the pair and a server stuck emitting on a
// generation the client can't decrypt.
//
// Idempotency with ABANDON (either order):
//   - ABANDON first: it re-assigns the peer epoch, so the epoch check
//     here fails and the auto-revert is a no-op.
//   - Auto-revert first: it restores the previous generation as active
//     and re-assigns the epoch, so a late ABANDON of the reverted
//     generation matches neither pending nor active and no-ops.
//   - Belt and braces, the kernel policy reqid is checked to still be the
//     activated generation's before flipping anything.
func (srv *Server) autoRevertIpipEspActivation(clientIP netip.Addr, epoch uint64, newSpiToServer uint32) {
	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	p, ok := srv.ipipPeers[clientIP]
	if !ok || p.espRekeyEpoch != epoch {
		log.Printf("[%v] esp activation gate expired for %v (spi to-server 0x%x) but a newer request superseded it; not reverting",
			srv.BindAddr, clientIP, newSpiToServer)
		return
	}
	if !p.espPrevReqidValid {
		log.Printf("[%v] esp AUTO-REVERT impossible for %v: activation gate expired (no packets on inbound spi 0x%x) but no pre-activation policy reqid is recorded; leaving policy as-is, next rotation heals",
			srv.BindAddr, clientIP, newSpiToServer)
		return
	}
	activatedReqid := ipipEspReqid(p.espSpiToClient)
	curReqid, found, err := srv.outboundIpipEspPolicyReqid(clientIP)
	if err != nil {
		log.Printf("[%v] esp AUTO-REVERT aborted for %v: cannot read outbound policy: %v",
			srv.BindAddr, clientIP, err)
		return
	}
	if !found || curReqid != activatedReqid {
		log.Printf("[%v] esp auto-revert for %v: outbound policy no longer selects the activated generation (reqid 0x%x, want 0x%x); already reverted or superseded, nothing to do",
			srv.BindAddr, clientIP, curReqid, activatedReqid)
		return
	}

	_, polOut := srv.ipipEspPolicies(clientIP, p.espPrevReqid)
	if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
		log.Printf("[%v] esp AUTO-REVERT FAILED for %v: flip outbound policy back to reqid 0x%x: %v; pair may be emitting on an unproven generation",
			srv.BindAddr, clientIP, p.espPrevReqid, err)
		return
	}
	log.Printf("[%v] esp AUTO-REVERT for ipip peer %v (%s): activation gate expired with zero packets on new inbound (spi 0x%x); outbound policy flipped back to reqid 0x%x (spi to-client 0x%x restored as active). The client never proved the generation (failed switch or lost ABANDON); its states stay installed until a later rotation sweeps them",
		srv.BindAddr, clientIP, p.ifname, newSpiToServer, p.espPrevReqid, p.espPrevSpiToClient)

	p.espSpiToServer, p.espSpiToClient = p.espPrevSpiToServer, p.espPrevSpiToClient
	p.espPrevSpiToServer, p.espPrevSpiToClient = 0, 0
	p.espPrevReqid, p.espPrevReqidValid = 0, false
	// Supersede the activation's epoch so a duplicate/late ABANDON (or any
	// other goroutine keyed to the activation) is a strict no-op.
	p.espRekeyEpoch = srv.nextEspEpochLocked()
}

// ipipEspPendingReapLoop deletes a prepared generation the client never
// followed up on (helper killed between PREPARE and its local install).
// Any request that touches the pair meanwhile re-assigns the epoch and
// disarms this reap; the next PREPARE also drops a stale pending directly.
// Active and previous generations are never touched here.
func (srv *Server) ipipEspPendingReapLoop(clientIP netip.Addr, epoch uint64, spiToServer, spiToClient uint32) {
	select {
	case <-srv.Ctx.Done():
		return
	case <-time.After(ipipEspPendingReap):
	}

	srv.ipipMu.Lock()
	defer srv.ipipMu.Unlock()

	p, ok := srv.ipipPeers[clientIP]
	if !ok || p.espRekeyEpoch != epoch ||
		p.espPendingSpiToServer != spiToServer || p.espPendingSpiToClient != spiToClient {
		return
	}
	srv.dropPendingEspGenLocked(p, "never activated or abandoned (reap timeout)")
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
			Reqid:   s.Reqid,
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
