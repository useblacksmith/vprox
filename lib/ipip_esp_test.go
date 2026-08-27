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
