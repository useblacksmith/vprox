package lib

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
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
//
// Rekey. The SAs have no lifetimes and no ESN (macOS setkey cannot install
// ESN), so a non-ESN SA hard-stops at seq 2^32; clients must rotate SA
// generations before that. {"esp": true, "rekey": true} is the rotation
// request: the server mints a fresh generation, installs only its new
// INBOUND (client->server) SA alongside the existing ones, and returns the
// material. Its outbound is switched to the new generation by a background
// poll once the new inbound SA's packet counter first ticks (i.e. the
// client demonstrably transmits on the new generation), or after a timeout.
// Old generations are garbage-collected a grace period after a
// counter-confirmed switch; a timeout-switch skips GC because the client
// may have rolled back to the previous generation (its health check
// failed), and deleting that generation's inbound SA would cut it off. The
// GC sweep is list-based (delete everything for the pair except the
// current generation), so it also collects generations orphaned by a vprox
// restart losing the in-memory map.
//
// A plain {"esp": true} (no rekey) keeps the original destructive-replace
// semantics for fresh connects: delete every SA for the pair, install one
// new generation. A rekey request for a pair with no live SAs falls back
// to that same full install.

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
// Old clients send an empty body or {} and get plaintext IPIP. Rekey asks
// for an additive SA-generation rotation instead of a destructive replace;
// it is only meaningful with Esp (see validate).
type connectIpipRequest struct {
	Esp   bool `json:"esp"`
	Rekey bool `json:"rekey"`
}

// validate rejects request combinations that have no defined semantics.
func (r connectIpipRequest) validate() error {
	if r.Rekey && !r.Esp {
		return fmt.Errorf("rekey requires esp")
	}
	return nil
}

// ipipEspStateKey identifies one kernel ESP state by direction and SPI.
// The rekey switch and GC paths work on these instead of full xfrm states
// so the selection logic is pure and testable off-Linux. AddTime is the
// kernel's install timestamp (seconds), used to pick the newest previous
// inbound generation; it survives vprox restarts because it lives in the
// kernel, not in this process.
type ipipEspStateKey struct {
	Src     netip.Addr
	Dst     netip.Addr
	Spi     uint32
	AddTime uint64
}

// newestIpipEspInboundSpi returns the SPI of the newest (by kernel
// AddTime) client->server state other than excludeSpi, or 0 if none. A
// rekey protects this generation from the post-switch GC: the client's
// rollback path returns its outbound to exactly this generation, and
// "vprox keeps accepting both" is the rollback contract. Using kernel
// AddTime (not in-memory bookkeeping) keeps the choice correct across
// vprox restarts.
func newestIpipEspInboundSpi(states []ipipEspStateKey, client, server netip.Addr, excludeSpi uint32) uint32 {
	var best ipipEspStateKey
	found := false
	for _, s := range states {
		if s.Src != client || s.Dst != server || s.Spi == excludeSpi {
			continue
		}
		if !found || s.AddTime > best.AddTime {
			best = s
			found = true
		}
	}
	if !found {
		return 0
	}
	return best.Spi
}

// ipipEspStatesToDelete returns the states flowing src->dst whose SPI is
// not in keep. States for other address pairs (or the reverse direction)
// are never selected. The rekey outbound switch uses it with the new
// generation's SPI as the only keeper; GC uses it per direction with the
// current generation pair, which also sweeps generations orphaned by a
// restart that lost the in-memory bookkeeping.
func ipipEspStatesToDelete(states []ipipEspStateKey, src, dst netip.Addr, keep map[uint32]struct{}) []ipipEspStateKey {
	var victims []ipipEspStateKey
	for _, s := range states {
		if s.Src != src || s.Dst != dst {
			continue
		}
		if _, keepIt := keep[s.Spi]; keepIt {
			continue
		}
		victims = append(victims, s)
	}
	return victims
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
