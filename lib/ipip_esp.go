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

// ipipEspAlgorithm is the transform used for IPIP ESP, as a wire-protocol
// name shared with the Mac client: AES-128-CBC encryption with
// HMAC-SHA-256 authentication truncated to 96 bits. AES-GCM would be
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
