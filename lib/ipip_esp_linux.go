//go:build linux

package lib

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
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

// Housekeeping timing. The pending deadline reaps a PREPAREd generation
// the client never activated (its actor died or walked away; there is no
// abandon op, the deadline IS the cleanup path). The GC grace lets
// in-flight packets on a superseded generation drain after the client
// provably switched (counter gate) before its states are deleted. Both
// are env-overridable so staging can exercise the sweep at seconds scale;
// never override in production.
const (
	defaultIpipEspPendingDeadline = 5 * time.Minute
	defaultIpipEspGcGrace         = 2 * time.Minute
	ipipHousekeepingInterval      = 5 * time.Second
	ipipSweepLogEvery             = 10 * time.Minute
)

func ipipEspPendingDeadline() time.Duration {
	if v := os.Getenv("VPROX_ESP_PENDING_DEADLINE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultIpipEspPendingDeadline
}

func ipipEspGcGrace() time.Duration {
	if v := os.Getenv("VPROX_ESP_GC_GRACE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultIpipEspGcGrace
}

// ipipEspReqid returns the xfrm reqid for a generation, derived from its
// SpiToClient. reqids exist to make OUTBOUND state selection deterministic:
// the out-policy template selects states by EXACT reqid match (verified on
// staging: a tmpl reqid never matches a state with a different reqid,
// including 0), so multiple outbound generations coexist and a policy
// update flips emission between them without deleting anything -- and
// without resetting sequence counters. Deriving the reqid from the SPI
// (instead of a counter) keeps it recoverable after a vprox restart from
// kernel state alone, which is also what makes the activate fence work:
// the policy's current reqid IS the active generation's identity.
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
// op=connect re-mints; old SPIs are deleted first so the kernel holds
// exactly one SA per direction). It also drops the tunnel MTU to fit the
// ESP overhead. On failure the partially installed state is removed
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

// prepareIpipEsp is op=prepare. Caller must hold ipipMu and have minted
// keys. It installs BOTH of the new generation's states -- the inbound
// next to every existing inbound, and the outbound under the generation's
// fresh reqid, which the (untouched) outbound policy does not select -- so
// nothing changes on the wire: the pair keeps flowing on the active
// generation in both directions. A later fenced ACTIVATE flips emission.
//
// A previously prepared-but-never-activated generation is replaced here
// (its states deleted); the housekeeping sweep handles the case where no
// next prepare ever comes.
//
// If the pair has no live outbound SA (fresh connect that asked for
// prepare, or a rebooted box that lost kernel state), this falls back to
// the destructive full install and reports fresh=true -- there is nothing
// to hand over from, and the client must know its old generation is gone.
func (srv *Server) prepareIpipEsp(p *ipipPeer, keys ipipEspKeys) (fresh bool, err error) {
	states, err := srv.listIpipEspStates()
	if err != nil {
		return false, fmt.Errorf("list esp states for prepare: %v", err)
	}
	live := false
	for _, s := range states {
		if s.Src == srv.BindAddr && s.Dst == p.clientIP {
			live = true
			break
		}
	}
	if !live {
		log.Printf("[%v] esp prepare requested for %v (%s) without live SAs; performing full install",
			srv.BindAddr, p.clientIP, p.ifname)
		if err := srv.installIpipEsp(p.clientIP, p.ifname, keys); err != nil {
			return false, err
		}
		p.setActiveEspGeneration(keys.ToServer.Spi, keys.ToClient.Spi)
		return true, nil
	}

	// Replace a stale pending generation: the client never activated it
	// (its actor died between prepare and activate), so its states are
	// dead weight the kernel should not accumulate.
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
	p.espPreparedAt = time.Now()

	log.Printf("[%v] esp generation prepared for ipip peer %v (%s, spi to-server 0x%x, to-client 0x%x, reqid 0x%x; policy untouched)",
		srv.BindAddr, p.clientIP, p.ifname,
		keys.ToServer.Spi, keys.ToClient.Spi, ipipEspReqid(keys.ToClient.Spi))
	return false, nil
}

// dropPendingEspGenLocked deletes the peer's pending generation's kernel
// states (if any) and clears the pending bookkeeping. Caller must hold
// ipipMu. Never touches active generations.
func (srv *Server) dropPendingEspGenLocked(p *ipipPeer, why string) {
	if p.espPendingSpiToServer == 0 && p.espPendingSpiToClient == 0 {
		return
	}
	log.Printf("[%v] esp pending generation dropped for %v (spi to-server 0x%x, to-client 0x%x): %s",
		srv.BindAddr, p.clientIP, p.espPendingSpiToServer, p.espPendingSpiToClient, why)
	srv.deleteIpipEspStateBySpi(p.clientIP, srv.BindAddr, p.espPendingSpiToServer)
	srv.deleteIpipEspStateBySpi(srv.BindAddr, p.clientIP, p.espPendingSpiToClient)
	p.espPendingSpiToServer, p.espPendingSpiToClient = 0, 0
	p.espPreparedAt = time.Time{}
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

// ipipEspActivateStatus classifies a fenced activate outcome for the HTTP
// layer: ok (flipped or already active), conflict (fence rejected -- 409,
// nothing mutated), or an internal error.
type ipipEspActivateStatus int

const (
	ipipActivateOk ipipEspActivateStatus = iota
	ipipActivateConflict
	ipipActivateError
)

// activateIpipEsp is the fenced ACTIVATE: flip the outbound policy
// template to target's reqid IF AND ONLY IF the kernel policy currently
// selects expectedActive's generation (compare-and-swap on kernel truth).
// A delayed/replayed activate for a superseded generation therefore fails
// closed with a conflict and mutates nothing; activating the target that
// is already active is idempotent success. The previously emitting state
// is NOT deleted -- the housekeeping sweep GC's it after the counter-gated
// proof plus grace. Caller must hold ipipMu.
//
// currentActive (valid on ok and conflict) reports the generation the
// policy selects after the call, so a fenced-out client can resync its
// view of the pair without a second protocol.
func (srv *Server) activateIpipEsp(p *ipipPeer, target, expectedActive uint32) (status ipipEspActivateStatus, currentActive uint32, err error) {
	curReqid, found, err := srv.outboundIpipEspPolicyReqid(p.clientIP)
	if err != nil {
		return ipipActivateError, 0, err
	}
	if !found {
		return ipipActivateConflict, 0, fmt.Errorf("no outbound esp policy for the pair; prepare heals it")
	}
	if curReqid == ipipEspReqid(target) {
		log.Printf("[%v] esp activate for %v (target 0x%x): already active; idempotent ok",
			srv.BindAddr, p.clientIP, target)
		srv.recordActivateLocked(p, target)
		return ipipActivateOk, target, nil
	}
	if curReqid != ipipEspReqid(expectedActive) {
		return ipipActivateConflict, uint32(curReqid), fmt.Errorf(
			"activate fence: outbound policy selects reqid 0x%x, not expectedActive 0x%x; no mutation",
			curReqid, expectedActive)
	}

	// The target generation must exist in the kernel (prepared earlier --
	// by this process or by one that restarted since; the kernel is the
	// source of truth, not the peer struct).
	if _, err := netlink.XfrmStateGet(&netlink.XfrmState{
		Src:   addrToIp(srv.BindAddr),
		Dst:   addrToIp(p.clientIP),
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(target),
	}); err != nil {
		if xfrmNotFound(err) {
			return ipipActivateConflict, uint32(curReqid), fmt.Errorf("no prepared to-client state with spi 0x%x", target)
		}
		return ipipActivateError, 0, fmt.Errorf("look up prepared to-client state 0x%x: %v", target, err)
	}

	_, polOut := srv.ipipEspPolicies(p.clientIP, ipipEspReqid(target))
	if err := netlink.XfrmPolicyUpdate(polOut); err != nil {
		return ipipActivateError, 0, fmt.Errorf("flip outbound esp policy to reqid 0x%x: %v", ipipEspReqid(target), err)
	}
	srv.recordActivateLocked(p, target)
	log.Printf("[%v] esp generation activated for ipip peer %v (%s): outbound policy now reqid 0x%x (spi to-client 0x%x, to-server 0x%x); previous generation retained for the sweep's counter-gated GC",
		srv.BindAddr, p.clientIP, p.ifname, ipipEspReqid(target), target, p.espSpiToServer)
	return ipipActivateOk, target, nil
}

// recordActivateLocked updates the peer's transition bookkeeping after a
// successful (or idempotent) activate of target. Without the matching
// pending bookkeeping (activation after a vprox restart lost it) the
// active to-server SPI is unknown, which keeps the sweep's counter gate
// closed for the pair -- the next successful rotation re-establishes it.
func (srv *Server) recordActivateLocked(p *ipipPeer, target uint32) {
	if p.espSpiToClient == target {
		return // duplicate activate; bookkeeping already reflects it
	}
	newToServer := uint32(0)
	if p.espPendingSpiToClient == target {
		newToServer = p.espPendingSpiToServer
	} else {
		log.Printf("[%v] esp activate for %v: to-server SPI unknown (restart mid-transition?); sweep GC stays gated until the next rotation",
			srv.BindAddr, p.clientIP)
	}
	p.espSpiToServer, p.espSpiToClient = newToServer, target
	p.espPendingSpiToServer, p.espPendingSpiToClient = 0, 0
	p.espPreparedAt = time.Time{}
	p.espActivatedAt = time.Now()
}

// listIpipEspStates lists all v4 ESP states as pure state infos (key +
// packet counter).
func (srv *Server) listIpipEspStates() ([]ipipEspStateInfo, error) {
	states, err := netlink.XfrmStateList(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list esp states: %v", err)
	}
	infos := make([]ipipEspStateInfo, 0, len(states))
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
		infos = append(infos, ipipEspStateInfo{
			ipipEspStateKey: ipipEspStateKey{
				Src:     src,
				Dst:     dst,
				Spi:     uint32(s.Spi),
				Reqid:   s.Reqid,
				AddTime: s.Statistics.AddTime,
			},
			Packets: s.Statistics.Packets,
		})
	}
	return infos, nil
}

// The single housekeeping sweep. One pass every 5 seconds:
//
//  1. vanished-peer reaping (kernel iface gone -> peer dropped), exactly
//     as before;
//  2. ESP transition housekeeping from ONE xfrm state dump plus one
//     policy read per peer: reap pendings past their deadline, counter-
//     gated GC of superseded generations, orphan aging. Snapshot under
//     ipipMu, dump WITHOUT the lock, re-validate under the lock before
//     mutating (a request that touched the pair meanwhile invalidates the
//     snapshot and the pass skips the peer -- next pass re-derives).
//
// Failed kernel ops stay retryable: the planner re-derives the same plan
// from kernel truth next pass. Sweep health is log-based (vprox has no
// prometheus): pass duration and error counters are logged periodically
// and on every error.
func (srv *Server) ipipHousekeepingLoop() {
	for {
		select {
		case <-srv.Ctx.Done():
			return
		case <-time.After(ipipHousekeepingInterval):
		}
		start := time.Now()
		srv.removeVanishedIpipPeers()
		err := srv.sweepIpipEsp()
		srv.noteSweepOutcome(time.Since(start), err)
	}
}

// noteSweepOutcome records one sweep pass and logs health: every error
// immediately, and a summary line at most every ipipSweepLogEvery.
func (srv *Server) noteSweepOutcome(took time.Duration, err error) {
	h := &srv.ipipSweepHealth
	h.passes.Add(1)
	now := time.Now()
	if err != nil {
		h.errors.Add(1)
		log.Printf("[%v] ipip housekeeping sweep FAILED after %v (pass %d, errors %d, last success %v): %v",
			srv.BindAddr, took.Round(time.Millisecond), h.passes.Load(), h.errors.Load(),
			time.Unix(h.lastSuccess.Load(), 0).Format(time.RFC3339), err)
		return
	}
	h.lastSuccess.Store(now.Unix())
	if now.Unix()-h.lastLogged.Load() >= int64(ipipSweepLogEvery/time.Second) {
		h.lastLogged.Store(now.Unix())
		log.Printf("[%v] ipip housekeeping healthy: pass %d took %v, %d error(s) total, last success %s",
			srv.BindAddr, h.passes.Load(), took.Round(time.Millisecond), h.errors.Load(),
			now.Format(time.RFC3339))
	}
}

// sweepIpipEsp is the ESP half of the housekeeping pass.
func (srv *Server) sweepIpipEsp() error {
	type peerSnap struct {
		clientIP netip.Addr
		peer     *ipipPeer
		in       espSweepPeerInput
	}

	srv.ipipMu.Lock()
	snaps := make([]peerSnap, 0, len(srv.ipipPeers))
	for clientIP, p := range srv.ipipPeers {
		snaps = append(snaps, peerSnap{
			clientIP: clientIP,
			peer:     p,
			in: espSweepPeerInput{
				Server:             srv.BindAddr,
				Client:             clientIP,
				ActiveSpiToServer:  p.espSpiToServer,
				PendingSpiToServer: p.espPendingSpiToServer,
				PendingSpiToClient: p.espPendingSpiToClient,
				PreparedAt:         p.espPreparedAt,
				ActivatedAt:        p.espActivatedAt,
			},
		})
	}
	srv.ipipMu.Unlock()

	if len(snaps) == 0 {
		return nil
	}

	// ONE xfrm dump per sweep, partitioned by pair below. Policy reads
	// are one cheap netlink get per peer. All without ipipMu.
	states, err := srv.listIpipEspStates()
	if err != nil {
		return err
	}

	deadline, grace := ipipEspPendingDeadline(), ipipEspGcGrace()
	now := time.Now()
	var errs []error
	for i := range snaps {
		s := &snaps[i]
		reqid, found, err := srv.outboundIpipEspPolicyReqid(s.clientIP)
		if err != nil {
			errs = append(errs, fmt.Errorf("peer %v: %v", s.clientIP, err))
			continue
		}
		s.in.PolicyReqid, s.in.PolicyFound = reqid, found
		s.in.Now, s.in.PendingDeadline, s.in.GcGrace = now, deadline, grace
		for _, st := range states {
			if (st.Src == srv.BindAddr && st.Dst == s.clientIP) ||
				(st.Src == s.clientIP && st.Dst == srv.BindAddr) {
				s.in.States = append(s.in.States, st)
			}
		}

		plan := planEspSweep(s.in)
		if !plan.ReapPending && len(plan.Deletions) == 0 {
			continue
		}

		// Re-validate under the lock: the peer must still be the live
		// entry AND its transition fields unchanged since the snapshot
		// (a request that touched the pair supersedes this pass).
		srv.ipipMu.Lock()
		cur, ok := srv.ipipPeers[s.clientIP]
		if !ok || cur != s.peer ||
			cur.espSpiToServer != s.in.ActiveSpiToServer ||
			cur.espPendingSpiToServer != s.in.PendingSpiToServer ||
			cur.espPendingSpiToClient != s.in.PendingSpiToClient ||
			!cur.espPreparedAt.Equal(s.in.PreparedAt) ||
			!cur.espActivatedAt.Equal(s.in.ActivatedAt) {
			srv.ipipMu.Unlock()
			continue
		}
		for _, d := range plan.Deletions {
			srv.deleteIpipEspStateBySpi(d.Src, d.Dst, d.Spi)
			log.Printf("[%v] esp sweep deleted state for %v (spi 0x%x, %v->%v)",
				srv.BindAddr, s.clientIP, d.Spi, d.Src, d.Dst)
		}
		if plan.ReapPending {
			// Clear pending bookkeeping only once the kernel confirms
			// the exact states are absent; otherwise keep it so the next
			// pass retries the delete.
			if srv.ipipEspStateAbsent(s.clientIP, srv.BindAddr, cur.espPendingSpiToServer) &&
				srv.ipipEspStateAbsent(srv.BindAddr, s.clientIP, cur.espPendingSpiToClient) {
				log.Printf("[%v] esp sweep reaped pending generation for %v (spi to-server 0x%x, to-client 0x%x): never activated within %v",
					srv.BindAddr, s.clientIP, cur.espPendingSpiToServer, cur.espPendingSpiToClient, deadline)
				cur.espPendingSpiToServer, cur.espPendingSpiToClient = 0, 0
				cur.espPreparedAt = time.Time{}
			} else {
				log.Printf("[%v] esp sweep could not confirm pending generation gone for %v; retrying next pass",
					srv.BindAddr, s.clientIP)
			}
		}
		srv.ipipMu.Unlock()
	}
	return errors.Join(errs...)
}

// ipipEspStateAbsent reports whether the src->dst state with the given SPI
// is confirmed absent from the kernel. spi 0 is trivially absent; a lookup
// error other than not-found is NOT absence.
func (srv *Server) ipipEspStateAbsent(src, dst netip.Addr, spi uint32) bool {
	if spi == 0 {
		return true
	}
	_, err := netlink.XfrmStateGet(&netlink.XfrmState{
		Src:   addrToIp(src),
		Dst:   addrToIp(dst),
		Proto: netlink.XFRM_PROTO_ESP,
		Spi:   int(spi),
	})
	return err != nil && xfrmNotFound(err)
}

// ipToAddr converts a net.IP to an IPv4 netip.Addr.
func ipToAddr(ip net.IP) (netip.Addr, bool) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(ipv4)), true
}
