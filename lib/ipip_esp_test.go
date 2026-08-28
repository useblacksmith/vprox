package lib

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMintIpipEspKeysShape(t *testing.T) {
	keys, err := mintIpipEspKeys()
	require.NoError(t, err)
	assert.Len(t, keys.ToServer.EncKey, ipipEspEncKeyLen)
	assert.Len(t, keys.ToServer.AuthKey, ipipEspAuthKeyLen)
	assert.Len(t, keys.ToClient.EncKey, ipipEspEncKeyLen)
	assert.Len(t, keys.ToClient.AuthKey, ipipEspAuthKeyLen)
	assert.NotEqual(t, keys.ToServer.EncKey, keys.ToClient.EncKey)
	assert.NotEqual(t, keys.ToServer.AuthKey, keys.ToClient.AuthKey)
	assert.GreaterOrEqual(t, keys.ToServer.Spi, uint32(ipipEspMinSpi),
		"SPIs 0-255 are reserved by RFC 4303")
	assert.GreaterOrEqual(t, keys.ToClient.Spi, uint32(ipipEspMinSpi))
	assert.NotEqual(t, keys.ToServer.Spi, keys.ToClient.Spi)
}

func TestMintIpipEspSpiAboveReservedRange(t *testing.T) {
	for i := 0; i < 64; i++ {
		spi, err := mintIpipEspSpi()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, spi, uint32(ipipEspMinSpi))
	}
}

func TestParseConnectIpipRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		version int
		op      string
	}{
		// Shapeless bodies still PARSE (so validate can return the
		// actionable wire-gate 400 instead of a JSON error), but they
		// never pass validate: version and op are mandatory.
		{"empty body", "", 0, ""},
		{"whitespace body", "  \n", 0, ""},
		{"empty object", "{}", 0, ""},
		{"legacy esp body", `{"esp": true}`, 0, ""},
		{"connect", `{"version":1,"op":"connect"}`, 1, "connect"},
		{"prepare", `{"version":1,"op":"prepare"}`, 1, "prepare"},
		{"unknown fields ignored", `{"version":1,"op":"connect","future":1}`, 1, "connect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parseConnectIpipRequest(strings.NewReader(tc.body))
			require.NoError(t, err)
			assert.Equal(t, tc.version, req.Version)
			assert.Equal(t, tc.op, req.Op)
		})
	}
}

// TestConnectIpipRequestValidate pins the wire gate: version and op are
// mandatory and validated before any peer lookup, activate requires both
// fence parameters, and no body shape (least of all the empty one) can
// imply a destructive install.
func TestConnectIpipRequestValidate(t *testing.T) {
	assert.NoError(t, connectIpipRequest{Version: 1, Op: "connect"}.validate())
	assert.NoError(t, connectIpipRequest{Version: 1, Op: "prepare"}.validate())
	assert.NoError(t, connectIpipRequest{
		Version: 1, Op: "activate", Target: "c0ffee42", ExpectedActive: "deadbeef",
	}.validate())

	assert.Error(t, connectIpipRequest{}.validate(), "empty body rejected")
	assert.Error(t, connectIpipRequest{Op: "connect"}.validate(), "missing version rejected")
	assert.Error(t, connectIpipRequest{Version: 2, Op: "connect"}.validate(), "unknown version rejected")
	assert.Error(t, connectIpipRequest{Version: 1}.validate(), "missing op rejected")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "abandon"}.validate(), "abandon no longer exists")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "rekey"}.validate(), "unknown op rejected")

	assert.Error(t, connectIpipRequest{Version: 1, Op: "activate", Target: "c0ffee42"}.validate(),
		"activate without expectedActive rejected: the fence is mandatory")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "activate", ExpectedActive: "c0ffee42"}.validate(),
		"activate without target rejected")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "activate", Target: "zzzz", ExpectedActive: "c0ffee42"}.validate(),
		"non-hex target rejected")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "activate", Target: "0", ExpectedActive: "c0ffee42"}.validate(),
		"zero target rejected")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "activate", Target: "100000000", ExpectedActive: "c0ffee42"}.validate(),
		"SPI wider than 32 bits rejected")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "connect", Target: "c0ffee42"}.validate(),
		"connect takes no target")
	assert.Error(t, connectIpipRequest{Version: 1, Op: "prepare", ExpectedActive: "c0ffee42"}.validate(),
		"prepare takes no expectedActive")

	// The version-gate 400 names both versions so it is actionable from
	// the client's log alone.
	err := connectIpipRequest{Version: 3, Op: "connect"}.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version 1")
}

func TestParseIpipEspSpiHex(t *testing.T) {
	spi, err := parseIpipEspSpiHex("c0ffee42")
	require.NoError(t, err)
	assert.Equal(t, uint32(0xc0ffee42), spi)
	_, err = parseIpipEspSpiHex("")
	assert.Error(t, err)
	_, err = parseIpipEspSpiHex("0")
	assert.Error(t, err)
}

// TestIpipPeerGenerationBookkeeping pins the pure peer-side state
// transitions.
func TestIpipPeerGenerationBookkeeping(t *testing.T) {
	p := &ipipPeer{}
	p.espPendingSpiToServer, p.espPendingSpiToClient = 0x200, 0x201
	p.espPreparedAt = time.Now()
	p.espActivatedAt = time.Now()
	p.setActiveEspGeneration(0x100, 0x101)
	assert.Equal(t, uint32(0x100), p.espSpiToServer)
	assert.Equal(t, uint32(0x101), p.espSpiToClient)
	assert.Zero(t, p.espPendingSpiToServer)
	assert.Zero(t, p.espPendingSpiToClient)
	assert.True(t, p.espPreparedAt.IsZero())
	assert.True(t, p.espActivatedAt.IsZero())
}

// Sweep planner fixtures.
var (
	sweepServer = netip.MustParseAddr("192.0.2.1")
	sweepClient = netip.MustParseAddr("192.0.2.2")
)

func sweepState(src, dst netip.Addr, spi uint32, reqid int, addTime, packets uint64) ipipEspStateInfo {
	return ipipEspStateInfo{
		ipipEspStateKey: ipipEspStateKey{Src: src, Dst: dst, Spi: spi, Reqid: reqid, AddTime: addTime},
		Packets:         packets,
	}
}

func baseSweepInput() espSweepPeerInput {
	return espSweepPeerInput{
		Server:          sweepServer,
		Client:          sweepClient,
		PolicyFound:     true,
		PolicyReqid:     0x201,
		Now:             time.Unix(10000, 0),
		PendingDeadline: 5 * time.Minute,
		GcGrace:         2 * time.Minute,
	}
}

func planSpis(plan espSweepPlan) []uint32 {
	spis := make([]uint32, 0, len(plan.Deletions))
	for _, d := range plan.Deletions {
		spis = append(spis, d.Spi)
	}
	return spis
}

// TestPlanEspSweepStableIsUntouched: a stable pair (one generation each
// way, no transition) is never touched.
func TestPlanEspSweepStableIsUntouched(t *testing.T) {
	in := baseSweepInput()
	in.ActiveSpiToServer = 0x200
	in.States = []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x200, 0, 3600, 12345),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 3600, 12345),
	}
	plan := planEspSweep(in)
	assert.False(t, plan.ReapPending)
	assert.Empty(t, plan.Deletions)
}

// TestPlanEspSweepPendingWithinDeadlinePinned: a live pending generation
// is never reaped or GC'd, no matter what else the sweep decides.
func TestPlanEspSweepPendingWithinDeadlinePinned(t *testing.T) {
	in := baseSweepInput()
	in.ActiveSpiToServer = 0x200
	in.PendingSpiToServer, in.PendingSpiToClient = 0x300, 0x301
	in.PreparedAt = in.Now.Add(-time.Minute)
	in.States = []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x200, 0, 3600, 12345),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 3600, 12345),
		sweepState(sweepClient, sweepServer, 0x300, 0, 60, 0),
		sweepState(sweepServer, sweepClient, 0x301, 0x301, 60, 0),
	}
	plan := planEspSweep(in)
	assert.False(t, plan.ReapPending)
	assert.Empty(t, plan.Deletions)
}

// TestPlanEspSweepPendingReapAfterDeadline: a pending generation past its
// deadline is reaped exactly (its two states), nothing else.
func TestPlanEspSweepPendingReapAfterDeadline(t *testing.T) {
	in := baseSweepInput()
	in.ActiveSpiToServer = 0x200
	in.PendingSpiToServer, in.PendingSpiToClient = 0x300, 0x301
	in.PreparedAt = in.Now.Add(-6 * time.Minute)
	in.States = []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x200, 0, 3600, 12345),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 3600, 12345),
		sweepState(sweepClient, sweepServer, 0x300, 0, 400, 0),
		sweepState(sweepServer, sweepClient, 0x301, 0x301, 400, 0),
	}
	plan := planEspSweep(in)
	assert.True(t, plan.ReapPending)
	assert.ElementsMatch(t, []uint32{0x300, 0x301}, planSpis(plan))
}

// TestPlanEspSweepGcCounterGated: the superseded generation is GC'd only
// once the new active inbound shows packets AND the grace has elapsed.
func TestPlanEspSweepGcCounterGated(t *testing.T) {
	in := baseSweepInput()
	in.ActiveSpiToServer = 0x200
	in.ActivatedAt = in.Now.Add(-3 * time.Minute) // grace elapsed
	old := []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x100, 0, 7200, 999999),     // superseded inbound
		sweepState(sweepServer, sweepClient, 0x101, 0x101, 7200, 999999), // superseded outbound
	}
	active := []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x200, 0, 200, 0), // no packets yet!
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 200, 50),
	}
	in.States = append(old, active...)

	plan := planEspSweep(in)
	assert.Empty(t, plan.Deletions,
		"zero packets on the active inbound: the client has not proven its switch; nothing is deleted")

	in.States[2].Packets = 7 // switch proven on the wire
	plan = planEspSweep(in)
	assert.ElementsMatch(t, []uint32{0x100, 0x101}, planSpis(plan),
		"counter + grace open the gate: exactly the superseded generation is swept")

	in.ActivatedAt = in.Now.Add(-30 * time.Second) // grace NOT elapsed
	plan = planEspSweep(in)
	assert.Empty(t, plan.Deletions, "grace not elapsed: nothing is deleted")
}

// TestPlanEspSweepCounterUnknownSkips: the active inbound missing from the
// dump is UNKNOWN, not zero -- the gate stays closed.
func TestPlanEspSweepCounterUnknownSkips(t *testing.T) {
	in := baseSweepInput()
	in.ActiveSpiToServer = 0x200
	in.ActivatedAt = in.Now.Add(-time.Hour)
	in.States = []ipipEspStateInfo{
		// Active inbound 0x200 absent from the dump.
		sweepState(sweepClient, sweepServer, 0x100, 0, 7200, 999999),
		sweepState(sweepServer, sweepClient, 0x101, 0x101, 7200, 999999),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 200, 50),
	}
	plan := planEspSweep(in)
	assert.Empty(t, plan.Deletions)
}

// TestPlanEspSweepUnknownActiveInboundNeverDeletesInbounds: after a
// restart the active to-server SPI is unknown; no inbound may ever be
// deleted (we cannot know which one the client transmits on), while
// orphan outbounds age out on kernel AddTime.
func TestPlanEspSweepUnknownActiveInboundNeverDeletesInbounds(t *testing.T) {
	in := baseSweepInput()
	in.ActiveSpiToServer = 0 // restart: unknown
	in.States = []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x100, 0, 7200, 10),
		sweepState(sweepClient, sweepServer, 0x200, 0, 3600, 10),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 3600, 10), // policy-selected
		sweepState(sweepServer, sweepClient, 0x101, 0x101, 7200, 10), // orphan outbound, old
		sweepState(sweepServer, sweepClient, 0x301, 0x301, 30, 0),    // orphan outbound, young
	}
	plan := planEspSweep(in)
	assert.ElementsMatch(t, []uint32{0x101}, planSpis(plan),
		"only the AGED orphan outbound is swept; every inbound and the young orphan survive")
}

// TestPlanEspSweepMissingPolicySkipsGc: a missing outbound policy makes
// the pair ambiguous; only the pending reap may run.
func TestPlanEspSweepMissingPolicySkipsGc(t *testing.T) {
	in := baseSweepInput()
	in.PolicyFound = false
	in.ActiveSpiToServer = 0x200
	in.ActivatedAt = in.Now.Add(-time.Hour)
	in.States = []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x100, 0, 7200, 10),
		sweepState(sweepServer, sweepClient, 0x101, 0x101, 7200, 10),
		sweepState(sweepClient, sweepServer, 0x200, 0, 3600, 10),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 3600, 10),
	}
	plan := planEspSweep(in)
	assert.Empty(t, plan.Deletions)

	in.PendingSpiToServer, in.PendingSpiToClient = 0x300, 0x301
	in.PreparedAt = in.Now.Add(-10 * time.Minute)
	plan = planEspSweep(in)
	assert.True(t, plan.ReapPending, "pending reap still runs without a policy")
}

// TestPlanEspSweepOtherPairsNeverTouched: the planner only sees the pair's
// own states, but even a stray entry for another pair must never be
// selected.
func TestPlanEspSweepOtherPairsNeverTouched(t *testing.T) {
	other := netip.MustParseAddr("192.0.2.3")
	in := baseSweepInput()
	in.ActiveSpiToServer = 0x200
	in.ActivatedAt = in.Now.Add(-time.Hour)
	in.States = []ipipEspStateInfo{
		sweepState(sweepClient, sweepServer, 0x200, 0, 3600, 10),
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 3600, 10),
		sweepState(other, sweepServer, 0x999, 0, 7200, 10),
		sweepState(sweepServer, other, 0x998, 0x998, 7200, 10),
	}
	plan := planEspSweep(in)
	assert.Empty(t, plan.Deletions)
}

// TestNewestIpipEspToClientReqid pins the policy-heal selection: newest by
// kernel AddTime (seconds SINCE install; smaller is newer), excluding the
// just-prepared generation.
func TestNewestIpipEspToClientReqid(t *testing.T) {
	other := netip.MustParseAddr("192.0.2.3")
	aged := []ipipEspStateInfo{
		sweepState(sweepServer, sweepClient, 0x101, 0, 300, 0),     // legacy gen, oldest
		sweepState(sweepServer, sweepClient, 0x201, 0x201, 200, 0), // current gen
		sweepState(sweepServer, sweepClient, 0x301, 0x301, 100, 0), // freshly prepared
		sweepState(sweepClient, sweepServer, 0x200, 0, 150, 0),     // inbound: never a candidate
		sweepState(sweepServer, other, 0x998, 0x998, 10, 0),        // different pair
	}
	reqid, ok := newestIpipEspToClientReqid(aged, sweepServer, sweepClient, 0x301)
	assert.True(t, ok)
	assert.Equal(t, 0x201, reqid,
		"newest outbound excluding the just-prepared generation")

	reqid, ok = newestIpipEspToClientReqid(aged[:1], sweepServer, sweepClient, 0)
	assert.True(t, ok)
	assert.Equal(t, 0, reqid,
		"a legacy generation heals to a reqid-0 template, which selects it")

	_, ok = newestIpipEspToClientReqid(nil, sweepServer, sweepClient, 0)
	assert.False(t, ok, "no states -> nothing to heal to")
}

// TestIpipEspFinishInstall pins the transactional-install contract: once
// the xfrm objects are in the kernel, any later failure of the install
// path must unwind them (the client never receives the keys, so leftover
// require-ESP state would blackhole the pair).
func TestIpipEspFinishInstall(t *testing.T) {
	t.Run("success does not unwind", func(t *testing.T) {
		unwound := false
		err, unwindErr := ipipEspFinishInstall(
			func() error { return nil },
			func() error { unwound = true; return nil },
		)
		assert.NoError(t, err)
		assert.NoError(t, unwindErr)
		assert.False(t, unwound, "a successful install must keep its xfrm state")
	})

	t.Run("failure unwinds and returns the original error", func(t *testing.T) {
		unwound := false
		finishErr := errors.New("mtu set failed")
		err, unwindErr := ipipEspFinishInstall(
			func() error { return finishErr },
			func() error { unwound = true; return nil },
		)
		assert.ErrorIs(t, err, finishErr)
		assert.NoError(t, unwindErr)
		assert.True(t, unwound, "xfrm objects must be removed when the install fails late")
	})

	t.Run("unwind failure is reported alongside", func(t *testing.T) {
		finishErr := errors.New("iface lookup failed")
		unwindFailure := errors.New("xfrm delete failed")
		err, unwindErr := ipipEspFinishInstall(
			func() error { return finishErr },
			func() error { return unwindFailure },
		)
		assert.ErrorIs(t, err, finishErr, "the install failure stays the primary error")
		assert.ErrorIs(t, unwindErr, unwindFailure)
	})
}

func TestParseConnectIpipRequestRejectsGarbage(t *testing.T) {
	_, err := parseConnectIpipRequest(strings.NewReader("not json"))
	assert.Error(t, err)
}

// TestConnectIpipActivateResponseShape pins the op=activate response: no
// key material, just the address and the post-call active generation.
func TestConnectIpipActivateResponseShape(t *testing.T) {
	buf, err := json.Marshal(&connectIpipActivateResponse{
		AssignedAddr: "10.100.0.2/16",
		Active:       "c0ffee42",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"AssignedAddr": "10.100.0.2/16", "Active": "c0ffee42"}`, string(buf))
}

// TestConnectIpipConflictResponseShape pins the 409 body: the fence
// rejection carries the currently active generation so the client can
// resync without a second protocol.
func TestConnectIpipConflictResponseShape(t *testing.T) {
	buf, err := json.Marshal(&connectIpipConflictResponse{
		Error:  "activate fence: superseded",
		Active: "deadbeef",
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"Error": "activate fence: superseded", "Active": "deadbeef"}`, string(buf))
}

func TestConnectIpipResponseEspShape(t *testing.T) {
	keys, err := mintIpipEspKeys()
	require.NoError(t, err)
	buf, err := json.Marshal(&connectIpipConnectResponse{
		AssignedAddr: "10.100.0.2/16",
		Esp: &connectIpipEspResponse{
			Algorithm:       ipipEspAlgorithm,
			SpiToServer:     keys.ToServer.Spi,
			EncKeyToServer:  "00112233445566778899aabbccddeeff",
			AuthKeyToServer: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			SpiToClient:     keys.ToClient.Spi,
			EncKeyToClient:  "33221100ffeeddccbbaa998877665544",
			AuthKeyToClient: "33221100ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544",
		},
	})
	require.NoError(t, err)

	var decoded struct {
		AssignedAddr string
		Esp          struct {
			Algorithm       string
			SpiToServer     uint32
			EncKeyToServer  string
			AuthKeyToServer string
			SpiToClient     uint32
			EncKeyToClient  string
			AuthKeyToClient string
		}
	}
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.Equal(t, "10.100.0.2/16", decoded.AssignedAddr)
	assert.Equal(t, "aes-cbc+hmac-sha256", decoded.Esp.Algorithm)
	assert.Equal(t, keys.ToServer.Spi, decoded.Esp.SpiToServer)
	assert.Equal(t, keys.ToClient.Spi, decoded.Esp.SpiToClient)
	assert.Len(t, decoded.Esp.EncKeyToServer, 2*ipipEspEncKeyLen)
	assert.Len(t, decoded.Esp.AuthKeyToServer, 2*ipipEspAuthKeyLen)
	assert.Len(t, decoded.Esp.EncKeyToClient, 2*ipipEspEncKeyLen)
	assert.Len(t, decoded.Esp.AuthKeyToClient, 2*ipipEspAuthKeyLen)
}
