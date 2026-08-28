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
		{"empty body (old client)", "", false, false},
		{"whitespace body", "  \n", false, false},
		{"empty object (old client)", "{}", false, false},
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
	assert.NoError(t, connectIpipRequest{}.validate())
	assert.NoError(t, connectIpipRequest{Esp: true}.validate())
	assert.NoError(t, connectIpipRequest{Esp: true, Rekey: true}.validate())
	assert.Error(t, connectIpipRequest{Rekey: true}.validate(),
		"rekey without esp has no defined semantics")
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

	t.Run("newest previous inbound is protected", func(t *testing.T) {
		aged := []ipipEspStateKey{
			{Src: client, Dst: server, Spi: 0x100, AddTime: 100}, // oldest
			{Src: client, Dst: server, Spi: 0x200, AddTime: 200}, // rollback target
			{Src: client, Dst: server, Spi: 0x300, AddTime: 300}, // freshly minted
			{Src: server, Dst: client, Spi: 0x201, AddTime: 200}, // outbound: never a candidate
			{Src: other, Dst: server, Spi: 0x999, AddTime: 999},  // different pair
		}
		assert.Equal(t, uint32(0x200),
			newestIpipEspInboundSpi(aged, client, server, 0x300),
			"newest inbound excluding the just-minted generation")
		assert.Equal(t, uint32(0x300),
			newestIpipEspInboundSpi(aged, client, server, 0),
			"without exclusion the newest inbound wins")
		assert.Equal(t, uint32(0),
			newestIpipEspInboundSpi(nil, client, server, 0),
			"no states -> no protected generation")
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

// TestConnectIpipResponsePlaintextShapeUnchanged pins the compat contract:
// a response without ESP marshals exactly like the pre-ESP server's, so old
// clients (and new clients talking plaintext) see no new fields.
func TestConnectIpipResponsePlaintextShapeUnchanged(t *testing.T) {
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
