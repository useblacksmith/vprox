package lib

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMintIpipEspKeysShape(t *testing.T) {
	keys, err := mintIpipEspKeys()
	require.NoError(t, err)
	assert.Len(t, keys.KeyToServer, ipipEspKeyLen)
	assert.Len(t, keys.KeyToClient, ipipEspKeyLen)
	assert.NotEqual(t, keys.KeyToServer, keys.KeyToClient)
	assert.GreaterOrEqual(t, keys.SpiToServer, uint32(ipipEspMinSpi),
		"SPIs 0-255 are reserved by RFC 4303")
	assert.GreaterOrEqual(t, keys.SpiToClient, uint32(ipipEspMinSpi))
	assert.NotEqual(t, keys.SpiToServer, keys.SpiToClient)
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
		name string
		body string
		esp  bool
	}{
		{"empty body (old client)", "", false},
		{"whitespace body", "  \n", false},
		{"empty object (old client)", "{}", false},
		{"esp false", `{"esp": false}`, false},
		{"esp true", `{"esp": true}`, true},
		{"unknown fields ignored", `{"esp": true, "future": 1}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := parseConnectIpipRequest(strings.NewReader(tc.body))
			require.NoError(t, err)
			assert.Equal(t, tc.esp, req.Esp)
		})
	}
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
			Algorithm:   ipipEspAlgorithm,
			SpiToServer: keys.SpiToServer,
			KeyToServer: "00112233445566778899aabbccddeeff00112233",
			SpiToClient: keys.SpiToClient,
			KeyToClient: "33221100ffeeddccbbaa99887766554433221100",
		},
	})
	require.NoError(t, err)

	var decoded struct {
		AssignedAddr string
		Esp          struct {
			Algorithm   string
			SpiToServer uint32
			KeyToServer string
			SpiToClient uint32
			KeyToClient string
		}
	}
	require.NoError(t, json.Unmarshal(buf, &decoded))
	assert.Equal(t, "10.100.0.2/16", decoded.AssignedAddr)
	assert.Equal(t, "rfc4106(gcm(aes))", decoded.Esp.Algorithm)
	assert.Equal(t, keys.SpiToServer, decoded.Esp.SpiToServer)
	assert.Equal(t, keys.SpiToClient, decoded.Esp.SpiToClient)
	assert.Len(t, decoded.Esp.KeyToServer, 2*ipipEspKeyLen)
	assert.Len(t, decoded.Esp.KeyToClient, 2*ipipEspKeyLen)
}
