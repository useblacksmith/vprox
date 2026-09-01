package lib

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

// ESP for IPIP tunnels.
//
// ESP is MANDATORY on the IPIP outer path (client <-> srv.BindAddr, IP
// proto 4). On connect the server mints one SA per direction (SPI + keys),
// installs kernel xfrm state and a require-ESP policy for the proto-4
// traffic between the two hosts, and returns the key material in the
// response. The response rides the same TLS channel that already carries
// the bearer password, so no extra key-exchange protocol (IKE, DH) is
// needed.
//
// Rekey. The SAs have no lifetimes and no ESN (macOS setkey cannot install
// ESN), so a non-ESN SA hard-stops at seq 2^32; clients must rotate SA
// generations before that. Generations are FORWARD-ONLY: no SA is ever
// deleted and re-added (re-adding an outbound SA resets its sequence
// counter to zero while the peer's inbound anti-replay high-water mark
// survives, so every packet on the re-added SA is dropped as a replay on a
// mature tunnel), and a rotation NEVER walks backward -- there is no
// abandon, no revert, no rollback. A failed rotation either retries
// forward with a fresh generation or, after the client's single recovery
// budget is spent, terminates the tunnel entirely (the client owns that
// terminal procedure; see the FA agent).
//
// The wire protocol is /connect-ipip v1, explicit op (see
// connectIpipRequest):
//
//	{"version":1,"op":"connect"}  mint a fresh generation and DESTRUCTIVELY
//	         replace whatever the kernel holds for the pair (fresh-connect
//	         semantics; the client is building a new tunnel).
//	{"version":1,"op":"prepare"}  mint generation N+1 and install BOTH its
//	         states -- the new inbound (client->server, reqid 0 like every
//	         inbound) and the new outbound (server->client) under a fresh
//	         reqid -- WITHOUT flipping the outbound policy. The kernel
//	         keeps emitting generation N (xfrm policy templates select
//	         states by exact reqid match), and every old state is
//	         untouched. The minted material is returned to the client.
//	{"version":1,"op":"activate","target":"<hex>","expectedActive":"<hex>"}
//	         flip the outbound policy to target's reqid, FENCED by a
//	         compare-and-swap on the kernel policy: the flip happens only
//	         if the policy currently selects expectedActive's generation.
//	         A delayed or replayed activate for a superseded generation
//	         fails with 409 and mutates NOTHING. Activating the already-
//	         active target is idempotent success. The old outbound STATE
//	         is retained (the housekeeper GC's it later on dataplane
//	         evidence), so an unproven flip never destroys the old path.
//
// Missing/unknown version or op is rejected with 400 BEFORE any peer
// lookup or mutation; an empty body can never imply a destructive install.
//
// There are no request flags: ESP is implied (connect and prepare always
// return minted keys) and there is no rekey/esp boolean, no espRekeyV
// version gate (the versioned op IS the gate), and no abandon op.
//
// Failure handling is owned by ONE housekeeping sweep (see
// ipipHousekeepingLoop), not per-request goroutines: prepared-but-never-
// activated generations are reaped after a deadline, superseded
// generations are GC'd only after the counter-gated proof that the client
// transmits on the new generation plus a grace period, and vanished peers
// are reaped as before. Nothing in the sweep ever touches the active
// generation, a pending generation within its deadline, or anything a
// transition still references.

// ipipEspAlgorithm is the transform used for IPIP ESP, as a wire-protocol
// name shared with the Mac client: AES-128-CBC encryption with
// HMAC-SHA-256 authentication truncated to 128 bits. AES-GCM would be
// preferable (one key, AEAD), but macOS setkey's PF_KEY grammar has no
// AEAD tokens at all (verified on macOS 26: "syntax error at [aes-gcm]"),
// so CBC+HMAC is the strongest transform both kernels can install.
const ipipEspAlgorithm = "aes-cbc+hmac-sha256"

// ipipEspEncKeyLen is the AES-128-CBC key length in bytes.
const ipipEspEncKeyLen = 16

// ipipEspAuthKeyLen is the HMAC-SHA-256 key length in bytes.
const ipipEspAuthKeyLen = 32

// ipipEspICVBits is the HMAC-SHA-256 truncation, in bits. macOS xnu
// implements RFC 4868 (128-bit truncation) for sha2-256 -- verified on
// staging by ESP packet-length math and XfrmInStateProtoError counters
// when Linux was set to the legacy 96-bit KAME truncation.
const ipipEspICVBits = 128

// ipipEspMinSpi is the smallest SPI we mint; SPIs 0-255 are reserved by
// RFC 4303.
const ipipEspMinSpi = 0x100

// ipipEspSA is one freshly minted SA: an SPI, an AES-CBC key, and an
// HMAC-SHA-256 key.
type ipipEspSA struct {
	Spi     uint32
	EncKey  []byte
	AuthKey []byte
}

// ipipEspKeys is one freshly minted SA pair for a client. Directions are
// named from the traffic's perspective so neither side has to reason about
// whose "in" it is: ToServer protects client->server packets, ToClient
// protects server->client packets.
type ipipEspKeys struct {
	ToServer ipipEspSA
	ToClient ipipEspSA
}

// mintIpipEspKeys mints two SPIs and two key sets from crypto/rand.
func mintIpipEspKeys() (ipipEspKeys, error) {
	toServer, err := mintIpipEspSA()
	if err != nil {
		return ipipEspKeys{}, err
	}
	toClient, err := mintIpipEspSA()
	for err == nil && toClient.Spi == toServer.Spi {
		toClient, err = mintIpipEspSA()
	}
	if err != nil {
		return ipipEspKeys{}, err
	}
	return ipipEspKeys{ToServer: toServer, ToClient: toClient}, nil
}

func mintIpipEspSA() (ipipEspSA, error) {
	spi, err := mintIpipEspSpi()
	if err != nil {
		return ipipEspSA{}, err
	}
	sa := ipipEspSA{
		Spi:     spi,
		EncKey:  make([]byte, ipipEspEncKeyLen),
		AuthKey: make([]byte, ipipEspAuthKeyLen),
	}
	if _, err := rand.Read(sa.EncKey); err != nil {
		return ipipEspSA{}, fmt.Errorf("mint esp enc key: %v", err)
	}
	if _, err := rand.Read(sa.AuthKey); err != nil {
		return ipipEspSA{}, fmt.Errorf("mint esp auth key: %v", err)
	}
	return sa, nil
}

// mintIpipEspSpi mints a random SPI outside the RFC 4303 reserved range.
func mintIpipEspSpi() (uint32, error) {
	var buf [4]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("mint esp spi: %v", err)
		}
		spi := binary.BigEndian.Uint32(buf[:])
		if spi >= ipipEspMinSpi {
			return spi, nil
		}
	}
}

// ipipWireVersion is the /connect-ipip protocol version. Requests whose
// version does not match are rejected with 400 before any peer lookup:
// the two sides of the rotation protocol must be deployed from matching
// revisions, and the explicit version on every request is what enforces
// that mechanically.
const ipipWireVersion = 1

// /connect-ipip ops.
const (
	ipipOpConnect  = "connect"
	ipipOpPrepare  = "prepare"
	ipipOpActivate = "activate"
)

// connectIpipRequest is the JSON body of POST /connect-ipip. Version and
// Op are mandatory: a missing/unknown version or op -- including the
// empty body -- is rejected with 400 before any peer lookup or mutation,
// so no request shape can ever imply a destructive install by accident.
// Target and ExpectedActive (lowercase hex SpiToClient values) are
// required by op=activate and forbidden elsewhere; ExpectedActive is the
// activate fence (see the package comment).
type connectIpipRequest struct {
	Version        int    `json:"version"`
	Op             string `json:"op"`
	Target         string `json:"target,omitempty"`
	ExpectedActive string `json:"expectedActive,omitempty"`
}

// validate enforces the wire gate. It runs in the handler BEFORE the peer
// map is consulted or any kernel object is touched.
func (r connectIpipRequest) validate() error {
	if r.Version != ipipWireVersion {
		return fmt.Errorf("unsupported /connect-ipip version %d (server speaks version %d); deploy matching revisions", r.Version, ipipWireVersion)
	}
	switch r.Op {
	case ipipOpConnect, ipipOpPrepare:
		if r.Target != "" || r.ExpectedActive != "" {
			return fmt.Errorf("op %q takes no target/expectedActive", r.Op)
		}
	case ipipOpActivate:
		if _, err := parseIpipEspSpiHex(r.Target); err != nil {
			return fmt.Errorf("activate requires a valid target: %v", err)
		}
		if _, err := parseIpipEspSpiHex(r.ExpectedActive); err != nil {
			return fmt.Errorf("activate requires a valid expectedActive: %v", err)
		}
	case "":
		return fmt.Errorf("missing op (want connect|prepare|activate)")
	default:
		return fmt.Errorf("unknown op %q (want connect|prepare|activate)", r.Op)
	}
	return nil
}

// parseIpipEspSpiHex parses a generation's SpiToClient as sent by the
// client in activate requests.
func parseIpipEspSpiHex(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("invalid ESP SPI %q", s)
	}
	return uint32(v), nil
}

// ipipEspStateKey identifies one kernel ESP state by direction, SPI, and
// reqid. The sweep works on these instead of full xfrm states so the
// selection logic is pure and testable off-Linux. AddTime is the kernel's
// install timestamp (absolute, seconds since the epoch -- xfrm
// curlft.add_time), used to age orphan states; it survives vprox restarts
// because it lives in the kernel, not in this process.
type ipipEspStateKey struct {
	Src     netip.Addr
	Dst     netip.Addr
	Spi     uint32
	Reqid   int
	AddTime uint64
}

// ipipEspStateInfo is a state key plus the kernel packet counter, the
// dataplane evidence the sweep's GC gate keys on.
type ipipEspStateInfo struct {
	ipipEspStateKey
	Packets uint64
}

// newestIpipEspToClientReqid returns the reqid of the newest (by kernel
// AddTime, an absolute install timestamp in seconds since the epoch --
// larger is newer) server->client state other than excludeSpi. Used only
// to heal a missing outbound policy: the policy template must select the
// generation the pair was actually running on, and after a vprox restart
// the only source of truth is the kernel. ok is false when the pair has
// no such state.
func newestIpipEspToClientReqid(states []ipipEspStateInfo, server, client netip.Addr, excludeSpi uint32) (reqid int, ok bool) {
	var best ipipEspStateKey
	found := false
	for _, s := range states {
		if s.Src != server || s.Dst != client || s.Spi == excludeSpi {
			continue
		}
		if !found || s.AddTime > best.AddTime {
			best = s.ipipEspStateKey
			found = true
		}
	}
	return best.Reqid, found
}

// ipipEspFinishInstall runs finish (the post-xfrm steps of an ESP install:
// iface lookup and MTU clamp) and, if it fails, unwinds the xfrm objects
// that were already installed for the pair. The install must be
// transactional: on failure the handler returns an error to the client, so
// the client never receives the minted keys, and a pair left require-ESP'd
// in the kernel with keys nobody holds blackholes all IPIP traffic until a
// successful retry. The returned err is always the finish failure (nil on
// success); unwindErr reports the unwind's own outcome for logging.
func ipipEspFinishInstall(finish, unwind func() error) (err, unwindErr error) {
	if err = finish(); err == nil {
		return nil, nil
	}
	return err, unwind()
}

// ipipRequestBodyLimit bounds how much of the request body we read; the
// legitimate body is a few dozen bytes of JSON.
const ipipRequestBodyLimit = 4096

// parseConnectIpipRequest decodes the /connect-ipip body. An empty body
// parses to the zero request, which validate() then rejects (missing
// version and op); parse and validate are kept separate so the 400 names
// the protocol violation rather than a JSON error.
func parseConnectIpipRequest(body io.Reader) (connectIpipRequest, error) {
	var req connectIpipRequest
	data, err := io.ReadAll(io.LimitReader(body, ipipRequestBodyLimit))
	if err != nil {
		return req, fmt.Errorf("read request body: %v", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return req, nil
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, fmt.Errorf("parse request body: %v", err)
	}
	return req, nil
}

// ipipSweepHealth tracks the housekeeping sweep's pass/error counters and
// last success for the log-based health lines.
type ipipSweepHealth struct {
	passes      atomic.Uint64
	errors      atomic.Uint64
	lastSuccess atomic.Int64 // unix seconds
	lastLogged  atomic.Int64 // unix seconds
}

// Housekeeping sweep planning (pure; the Linux half feeds kernel dumps in
// and applies the plan out, see sweepIpipEsp).

// espSweepPeerInput is one peer's transition bookkeeping plus the kernel
// truth the sweep needs to decide what to reap.
type espSweepPeerInput struct {
	Server, Client netip.Addr

	// Kernel truth: the outbound policy's template reqid IS the active
	// generation (states are selected by exact reqid match).
	PolicyReqid int
	PolicyFound bool

	// Bookkept transition data (plain fields on the peer).
	ActiveSpiToServer  uint32 // 0 = unknown (adopted pair, restart)
	PendingSpiToServer uint32
	PendingSpiToClient uint32
	PreparedAt         time.Time
	ActivatedAt        time.Time

	Now             time.Time
	PendingDeadline time.Duration
	GcGrace         time.Duration

	// States for THIS pair only (both directions), with counters.
	States []ipipEspStateInfo
}

// espSweepPlan is the sweep's decision for one peer: which pending
// bookkeeping to clear and which exact states to delete. Failed deletions
// stay retryable next pass (the planner re-derives the same plan from
// kernel truth).
type espSweepPlan struct {
	ReapPending bool
	Deletions   []ipipEspStateKey
}

// planEspSweep decides, from kernel truth plus the peer's plain transition
// fields, which ESP states are reapable. The invariants, in order of
// precedence:
//
//   - The ACTIVE generation is never touched: the outbound state the
//     policy's reqid selects, and the bookkept active inbound.
//   - A pending generation within its deadline is never touched; past the
//     deadline its two states are reaped exactly (the client walked away
//     without activating -- there is no abandon op to tell us sooner).
//   - Superseded/orphan OUTBOUND states (not policy-selected, not pending)
//     are deleted only after the switch is confirmed on the wire -- the
//     active inbound's packet counter is nonzero, proof the client
//     transmits on the new generation -- plus a grace period since the
//     activate. Orphans with no transition bookkeeping at all (restart
//     leftovers) age out on the kernel's own AddTime instead.
//   - INBOUND states other than the active/pending ones are deleted under
//     the same counter gate; when the active inbound is UNKNOWN (adopted
//     pair before its first post-restart rotation) no inbound is ever
//     deleted -- we cannot know which one the client transmits on.
//   - A missing outbound policy makes the pair ambiguous: nothing but the
//     pending reap may run (the next prepare heals the policy).
//   - A counter that cannot be read is UNKNOWN, not zero: the active
//     inbound state missing from the dump skips the gate entirely.
func planEspSweep(in espSweepPeerInput) espSweepPlan {
	var plan espSweepPlan

	pendingSet := in.PendingSpiToServer != 0 || in.PendingSpiToClient != 0
	pendingExpired := pendingSet && !in.PreparedAt.IsZero() &&
		in.Now.Sub(in.PreparedAt) > in.PendingDeadline
	if pendingExpired {
		plan.ReapPending = true
		for _, s := range in.States {
			if (s.Src == in.Client && s.Dst == in.Server && s.Spi == in.PendingSpiToServer) ||
				(s.Src == in.Server && s.Dst == in.Client && s.Spi == in.PendingSpiToClient) {
				plan.Deletions = append(plan.Deletions, s.ipipEspStateKey)
			}
		}
	}

	if !in.PolicyFound {
		return plan
	}

	// Counter gate: the active inbound must exist in the dump and show
	// packets. Missing state = UNKNOWN, gate stays closed.
	counterConfirmed := false
	if in.ActiveSpiToServer != 0 {
		for _, s := range in.States {
			if s.Src == in.Client && s.Dst == in.Server && s.Spi == in.ActiveSpiToServer {
				counterConfirmed = s.Packets > 0
				break
			}
		}
	}
	graceElapsed := !in.ActivatedAt.IsZero() && in.Now.Sub(in.ActivatedAt) > in.GcGrace
	gcOpen := counterConfirmed && graceElapsed

	pendingLive := pendingSet && !pendingExpired

	for _, s := range in.States {
		switch {
		case s.Src == in.Server && s.Dst == in.Client: // outbound
			if s.Reqid == in.PolicyReqid {
				continue // active generation
			}
			if pendingLive && s.Spi == in.PendingSpiToClient {
				continue
			}
			if pendingExpired && s.Spi == in.PendingSpiToClient {
				continue // already in the reap set
			}
			if gcOpen {
				plan.Deletions = append(plan.Deletions, s.ipipEspStateKey)
				continue
			}
			// Orphan path: no transition references this state and no
			// bookkeeping exists to gate on -- age it out on kernel truth
			// (AddTime is the absolute install timestamp). The deadline
			// protects a transition prepared moments before a restart
			// whose activate arrives right after.
			if in.ActivatedAt.IsZero() && !pendingSet && s.AddTime > 0 &&
				in.Now.Sub(time.Unix(int64(s.AddTime), 0)) > in.PendingDeadline {
				plan.Deletions = append(plan.Deletions, s.ipipEspStateKey)
			}
		case s.Src == in.Client && s.Dst == in.Server: // inbound
			if in.ActiveSpiToServer == 0 {
				continue // unknown active inbound: never delete any
			}
			if s.Spi == in.ActiveSpiToServer {
				continue
			}
			if pendingLive && s.Spi == in.PendingSpiToServer {
				continue
			}
			if pendingExpired && s.Spi == in.PendingSpiToServer {
				continue // already in the reap set
			}
			if gcOpen {
				plan.Deletions = append(plan.Deletions, s.ipipEspStateKey)
			}
		}
	}
	return plan
}
