package relayproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
)

// Session authentication is a mutual proof of the shared relay password,
// bound to the TLS connection it travels on:
//
//	binding = TLS-Exporter(label="EXPORTER-blacksmith-relay", context="", 32 bytes)
//	Hello.Auth       = base64(HMAC-SHA256(key=password, "client" | binding))
//	HelloReply.Proof = base64(HMAC-SHA256(key=password, "server" | binding))
//
// Both sides derive the binding from their own end of the TLS 1.3
// connection (RFC 8446 §7.5), so a proof is valid on exactly one
// connection and cannot be replayed. The password never crosses the wire,
// the client learns the relay holds it before opening any stream, and the
// relay's certificate therefore needs no out-of-band trust anchor.
const (
	exporterLabel = "EXPORTER-blacksmith-relay"
	bindingLen    = 32
)

// ChannelBinding derives the per-connection binding from the TLS state.
func ChannelBinding(cs tls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(exporterLabel, nil, bindingLen)
}

// ClientProof is the value the client places in Hello.Auth.
func ClientProof(password string, binding []byte) string {
	return proof(password, "client", binding)
}

// ServerProof is the value the relay places in HelloReply.Proof.
func ServerProof(password string, binding []byte) string {
	return proof(password, "server", binding)
}

// VerifyProof compares a received proof with the expected one in constant
// time.
func VerifyProof(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func proof(password, role string, binding []byte) string {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte(role))
	mac.Write(binding)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
