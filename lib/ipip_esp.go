package lib

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// ESP for IPIP tunnels.
//
// The IPIP outer path (client <-> srv.BindAddr, IP proto 4) is plaintext by
// default. A client may opt in to ESP by sending {"esp": true} in the
// /connect-ipip body; the server then mints one SA per direction (SPI +
// AES-GCM key), installs kernel xfrm state and a require-ESP policy for the
// proto-4 traffic between the two hosts, and returns the key material in the
// response. The response rides the same TLS channel that already carries the
// bearer password, so no extra key-exchange protocol (IKE, DH) is needed.
// There is no rekey machinery: a repeated /connect-ipip with esp re-mints
// and replaces the pair's SAs.

// ipipEspAlgorithm is the AEAD used for IPIP ESP, in Linux crypto API
// notation. This is AES-GCM with a 128-bit ICV per RFC 4106; macOS setkey
// calls the same transform "aes-gcm-16". Chosen over aes-cbc+hmac because a
// single AEAD keeps one key per direction and both kernels support it.
const ipipEspAlgorithm = "rfc4106(gcm(aes))"

// ipipEspKeyLen is the RFC 4106 key material length: a 128-bit AES key
// followed by a 4-byte salt.
const ipipEspKeyLen = 20

// ipipEspICVBits is the AEAD integrity tag length in bits.
const ipipEspICVBits = 128

// ipipEspMinSpi is the smallest SPI we mint; SPIs 0-255 are reserved by
// RFC 4303.
const ipipEspMinSpi = 0x100

// ipipEspKeys is one freshly minted SA pair for a client. Directions are
// named from the traffic's perspective so neither side has to reason about
// whose "in" it is: ToServer protects client->server packets, ToClient
// protects server->client packets.
type ipipEspKeys struct {
	SpiToServer uint32
	KeyToServer []byte
	SpiToClient uint32
	KeyToClient []byte
}

// mintIpipEspKeys mints two SPIs and two AES-GCM keys from crypto/rand.
func mintIpipEspKeys() (ipipEspKeys, error) {
	spiToServer, err := mintIpipEspSpi()
	if err != nil {
		return ipipEspKeys{}, err
	}
	spiToClient, err := mintIpipEspSpi()
	for err == nil && spiToClient == spiToServer {
		spiToClient, err = mintIpipEspSpi()
	}
	if err != nil {
		return ipipEspKeys{}, err
	}

	keys := ipipEspKeys{
		SpiToServer: spiToServer,
		KeyToServer: make([]byte, ipipEspKeyLen),
		SpiToClient: spiToClient,
		KeyToClient: make([]byte, ipipEspKeyLen),
	}
	if _, err := rand.Read(keys.KeyToServer); err != nil {
		return ipipEspKeys{}, fmt.Errorf("mint esp key: %v", err)
	}
	if _, err := rand.Read(keys.KeyToClient); err != nil {
		return ipipEspKeys{}, fmt.Errorf("mint esp key: %v", err)
	}
	return keys, nil
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

// connectIpipRequest is the (optional) JSON body of POST /connect-ipip.
// Old clients send an empty body or {} and get plaintext IPIP.
type connectIpipRequest struct {
	Esp bool `json:"esp"`
}

// ipipRequestBodyLimit bounds how much of the request body we read; the
// legitimate body is a few bytes of JSON.
const ipipRequestBodyLimit = 4096

// parseConnectIpipRequest decodes the /connect-ipip body. An empty body is
// valid (old clients) and yields the zero request.
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
