package lib

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

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
		name  string
		body  string
		esp   bool
		rekey bool
	}{
		// Plaintext shapes still PARSE (so validate can return the
		// actionable "ESP required" 400 instead of a JSON error), but
		// they no longer pass validate -- ESP is mandatory.
		{"empty body (pre-ESP client, rejected by validate)", "", false, false},
		{"whitespace body", "  \n", false, false},
		{"empty object (pre-ESP client, rejected by validate)", "{}", false, false},
		{"esp false", `{"esp": false}`, false, false},
		{"esp true", `{"esp": true}`, true, false},
		{"esp rekey", `{"esp": true, "rekey": true}`, true, true},
		{"rekey false", `{"esp": true, "rekey": false}`, true, false},
		{"unknown fields ignored", `{"esp": true, "future": 1}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parseConnectIpipRequest(strings.NewReader(tc.body))
			require.NoError(t, err)
			assert.Equal(t, tc.esp, req.Esp)
			assert.Equal(t, tc.rekey, req.Rekey)
		})
	}
}

func TestConnectIpipRequestValidate(t *testing.T) {
	v := ipipEspRekeyVersion
	assert.NoError(t, connectIpipRequest{Esp: true}.validate())
	assert.NoError(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v}.validate())

	// ESP is mandatory: a plaintext body ({} or esp:false) is rejected with
	// an actionable "ESP required" message before any state is touched.
	err := connectIpipRequest{}.validate()
	require.Error(t, err, "plaintext {} rejected: ESP is mandatory")
	assert.Contains(t, err.Error(), "ESP required")
	assert.Error(t, connectIpipRequest{Rekey: true, EspRekeyV: v}.validate(),
		"rekey without esp rejected (plaintext, and no defined semantics)")

	assert.NoError(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v, Activate: "c0ffee42"}.validate())
	assert.NoError(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v, Abandon: "c0ffee42"}.validate())
	assert.Error(t, connectIpipRequest{Esp: true, Activate: "c0ffee42"}.validate(),
		"activate requires rekey")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v, Activate: "a", Abandon: "b"}.validate(),
		"activate and abandon are mutually exclusive")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v, Activate: "zzzz"}.validate(),
		"non-hex SPI rejected")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v, Activate: "0"}.validate(),
		"zero SPI rejected")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: v, Activate: "100000000"}.validate(),
		"SPI wider than 32 bits rejected")
}

// TestConnectIpipRequestVersionGate pins the espRekeyV contract: every
// rekey mutation must carry the exact protocol version; fresh ESP connects
// are exempt (pre-rekey agents never send rekey). Plaintext requests fail
// the mandatory-ESP check before the version gate is even consulted.
func TestConnectIpipRequestVersionGate(t *testing.T) {
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true}.validate(),
		"versionless rekey mutation rejected")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: 1}.validate(),
		"old-draft version rejected")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: ipipEspRekeyVersion + 1}.validate(),
		"future version rejected")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, EspRekeyV: 1, Activate: "c0ffee42"}.validate(),
		"activate with wrong version rejected")
	assert.Error(t, connectIpipRequest{Esp: true, Rekey: true, Abandon: "c0ffee42"}.validate(),
		"versionless abandon rejected")
	assert.NoError(t, connectIpipRequest{Esp: true}.validate(),
		"fresh ESP connect is exempt")
	assert.Error(t, connectIpipRequest{}.validate(),
		"plaintext request rejected by the mandatory-ESP check")

	// The version gate produces a message that names both versions so the
	// 4xx is actionable from the client's log alone.
	err := connectIpipRequest{Esp: true, Rekey: true}.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "espRekeyV 2")
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
// transitions of the rotation protocol.
func TestIpipPeerGenerationBookkeeping(t *testing.T) {
	p := &ipipPeer{}
	p.setActiveEspGeneration(0x100, 0x101)
	assert.Equal(t, uint32(0x100), p.espSpiToServer)
	assert.Equal(t, uint32(0x101), p.espSpiToClient)
	assert.Zero(t, p.espPendingSpiToServer)
	assert.Zero(t, p.espPrevSpiToServer)
	assert.False(t, p.espPrevReqidValid)

	p.espPendingSpiToServer, p.espPendingSpiToClient = 0x200, 0x201
	p.espPrevReqid, p.espPrevReqidValid = 0x42, true
	p.clearEspGenerations()
	assert.Zero(t, p.espSpiToServer)
	assert.Zero(t, p.espPendingSpiToClient)
	assert.False(t, p.espPrevReqidValid)
}

func TestIpipEspStatesToDelete(t *testing.T) {
	server := netip.MustParseAddr("192.0.2.1")
	client := netip.MustParseAddr("192.0.2.2")
	other := netip.MustParseAddr("192.0.2.3")

	states := []ipipEspStateKey{
		{Src: client, Dst: server, Spi: 0x100}, // old gen inbound
		{Src: client, Dst: server, Spi: 0x200}, // current gen inbound
		{Src: server, Dst: client, Spi: 0x101}, // old gen outbound
		{Src: server, Dst: client, Spi: 0x201}, // current gen outbound
		{Src: other, Dst: server, Spi: 0x999},  // different pair
		{Src: server, Dst: other, Spi: 0x998},  // different pair
	}

	t.Run("outbound switch keeps only new spi", func(t *testing.T) {
		victims := ipipEspStatesToDelete(states, server, client,
			map[uint32]struct{}{0x201: {}})
		require.Len(t, victims, 1)
		assert.Equal(t, uint32(0x101), victims[0].Spi)
	})

	t.Run("gc sweeps everything but current generation", func(t *testing.T) {
		keep := map[uint32]struct{}{0x200: {}, 0x201: {}}
		var victims []ipipEspStateKey
		victims = append(victims, ipipEspStatesToDelete(states, client, server, keep)...)
		victims = append(victims, ipipEspStatesToDelete(states, server, client, keep)...)
		require.Len(t, victims, 2)
		spis := []uint32{victims[0].Spi, victims[1].Spi}
		assert.ElementsMatch(t, []uint32{0x100, 0x101}, spis)
	})

	t.Run("gc after restart sweeps orphans it never knew", func(t *testing.T) {
		// After a vprox restart the map is lost; the keep-set contains only
		// the newest generation, and every other state for the pair -- no
		// matter how many generations accumulated -- is a victim.
		orphaned := append(states,
			ipipEspStateKey{Src: client, Dst: server, Spi: 0x300},
			ipipEspStateKey{Src: server, Dst: client, Spi: 0x301},
		)
		keep := map[uint32]struct{}{0x300: {}, 0x301: {}}
		var victims []ipipEspStateKey
		victims = append(victims, ipipEspStatesToDelete(orphaned, client, server, keep)...)
		victims = append(victims, ipipEspStatesToDelete(orphaned, server, client, keep)...)
		require.Len(t, victims, 4)
		for _, v := range victims {
			assert.NotContains(t, []uint32{0x300, 0x301, 0x999, 0x998}, v.Spi)
		}
	})

	t.Run("policy heal picks the newest outbound generation", func(t *testing.T) {
		aged := []ipipEspStateKey{
			{Src: server, Dst: client, Spi: 0x101, Reqid: 0, AddTime: 100},     // legacy gen
			{Src: server, Dst: client, Spi: 0x201, Reqid: 0x201, AddTime: 200}, // current gen
			{Src: server, Dst: client, Spi: 0x301, Reqid: 0x301, AddTime: 300}, // freshly prepared
			{Src: client, Dst: server, Spi: 0x200, Reqid: 0, AddTime: 250},     // inbound: never a candidate
			{Src: server, Dst: other, Spi: 0x998, Reqid: 0x998, AddTime: 999},  // different pair
		}
		reqid, ok := newestIpipEspToClientReqid(aged, server, client, 0x301)
		assert.True(t, ok)
		assert.Equal(t, 0x201, reqid,
			"newest outbound excluding the just-prepared generation")

		reqid, ok = newestIpipEspToClientReqid(aged[:1], server, client, 0)
		assert.True(t, ok)
		assert.Equal(t, 0, reqid,
			"a legacy generation heals to a reqid-0 template, which selects it")

		_, ok = newestIpipEspToClientReqid(nil, server, client, 0)
		assert.False(t, ok, "no states -> nothing to heal to")
	})

	t.Run("other pairs never selected", func(t *testing.T) {
		victims := ipipEspStatesToDelete(states, server, client, map[uint32]struct{}{})
		for _, v := range victims {
			assert.NotEqual(t, other, v.Src)
			assert.NotEqual(t, other, v.Dst)
		}
	})
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

// TestConnectIpipResponseBareShape pins the shape of responses that carry
// no key material (ACTIVATE and ABANDON): exactly the one AssignedAddr
// field, no Esp key. Plaintext responses no longer exist -- ESP is
// mandatory -- but the bare shape is still on the wire for those two
// rotation steps.
func TestConnectIpipResponseBareShape(t *testing.T) {
	buf, err := json.Marshal(&connectIpipResponse{AssignedAddr: "10.100.0.2/16"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"AssignedAddr": "10.100.0.2/16"}`, string(buf))
}

func TestConnectIpipResponseEspShape(t *testing.T) {
	keys, err := mintIpipEspKeys()
	require.NoError(t, err)
	buf, err := json.Marshal(&connectIpipResponse{
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
