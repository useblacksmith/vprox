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
// generations before that. Generations are FORWARD-ONLY: no SA is ever
// deleted and re-added (re-adding an outbound SA resets its sequence
// counter to zero while the peer's inbound anti-replay high-water mark
// survives, so every packet on the re-added SA is dropped as a replay on a
// mature tunnel). The client drives a three-step rotation:
//
//	PREPARE  {"esp":true,"rekey":true}: mint generation N+1, install BOTH
//	         its states -- the new inbound (client->server, reqid 0 like
//	         every inbound) and the new outbound (server->client) under a
//	         fresh reqid -- WITHOUT flipping the outbound policy. The
//	         kernel keeps emitting generation N (xfrm policy templates
//	         select states by exact reqid match), and every old state is
//	         untouched. The minted material is returned to the client.
//	ACTIVATE {"esp":true,"rekey":true,"activate":"<SpiToClient hex>"}:
//	         after the client has installed its inbound for N+1, flip the
//	         outbound policy template to N+1's reqid. The old outbound
//	         STATE is retained, so the flip is reversible without replay
//	         damage (Linux resumes the old state's sequence counter).
//	         Idempotent, keyed by the generation's SpiToClient.
//	ABANDON  {"esp":true,"rekey":true,"abandon":"<SpiToClient hex>"}:
//	         the client's on-the-wire proof of N+1 failed. If N+1 is still
//	         pending, its two states are deleted (nothing else changes).
//	         If N+1 was activated, the outbound policy is flipped back to
//	         the previous generation's reqid; the abandoned states stay
//	         installed until the next successful rotation's GC sweeps them.
//
// GC is gated on dataplane evidence, never wall clock alone: after an
// ACTIVATE, a background poll watches the new inbound SA's packet counter
// (the client's post-switch health check produces those packets); only
// once it ticks -- proof the client transmits on N+1 -- are the pair's
// other generations swept, after a grace period. On poll timeout nothing
// is deleted; the next successful rotation's sweep collects stragglers. A
// pending generation the client never activates is reaped after a timeout
// (or replaced by the next PREPARE) without touching active state.
//
// A plain {"esp": true} (no rekey) keeps the original destructive-replace
// semantics for fresh connects: delete every SA for the pair, install one
// new generation. A PREPARE for a pair with no live server->client SA
// falls back to that same full install and reports Fresh=true so the
// client knows the pair was rebuilt rather than rotated.

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
// for an additive SA-generation PREPARE instead of a destructive replace;
// Activate and Abandon are the follow-up steps of the forward-only
// rotation, each carrying the target generation's SpiToClient as lowercase
// hex (see the package comment). All three are only meaningful with Esp.
type connectIpipRequest struct {
	Esp      bool   `json:"esp"`
	Rekey    bool   `json:"rekey"`
	Activate string `json:"activate,omitempty"`
	Abandon  string `json:"abandon,omitempty"`
}

// validate rejects request combinations that have no defined semantics.
func (r connectIpipRequest) validate() error {
	if r.Rekey && !r.Esp {
		return fmt.Errorf("rekey requires esp")
	}
	if (r.Activate != "" || r.Abandon != "") && !(r.Esp && r.Rekey) {
		return fmt.Errorf("activate/abandon require esp and rekey")
	}
	if r.Activate != "" && r.Abandon != "" {
		return fmt.Errorf("activate and abandon are mutually exclusive")
	}
	for _, s := range []string{r.Activate, r.Abandon} {
		if s == "" {
			continue
		}
		if _, err := parseIpipEspSpiHex(s); err != nil {
			return err
		}
	}
	return nil
}

// parseIpipEspSpiHex parses a generation's SpiToClient as sent by the
// client in activate/abandon requests.
func parseIpipEspSpiHex(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("invalid ESP SPI %q", s)
	}
	return uint32(v), nil
}

// ipipEspStateKey identifies one kernel ESP state by direction, SPI, and
// reqid. The rekey and GC paths work on these instead of full xfrm states
// so the selection logic is pure and testable off-Linux. AddTime is the
// kernel's install timestamp (seconds), used to pick the newest existing
// generation when healing a lost outbound policy; it survives vprox
// restarts because it lives in the kernel, not in this process.
type ipipEspStateKey struct {
	Src     netip.Addr
	Dst     netip.Addr
	Spi     uint32
	Reqid   int
	AddTime uint64
}

// newestIpipEspToClientReqid returns the reqid of the newest (by kernel
// AddTime) server->client state other than excludeSpi. Used only to heal a
// missing outbound policy: the policy template must select the generation
// the pair was actually running on, and after a vprox restart the only
// source of truth is the kernel. Legacy states (installed before reqid'd
// generations) carry reqid 0, which is exactly the template value that
// selects them. ok is false when the pair has no such state.
func newestIpipEspToClientReqid(states []ipipEspStateKey, server, client netip.Addr, excludeSpi uint32) (reqid int, ok bool) {
	var best ipipEspStateKey
	found := false
	for _, s := range states {
		if s.Src != server || s.Dst != client || s.Spi == excludeSpi {
			continue
		}
		if !found || s.AddTime > best.AddTime {
			best = s
			found = true
		}
	}
	return best.Reqid, found
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
