package relayproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// Proof fixtures shared verbatim with the FastActions/fa copy of this
// package: password "pw", binding = bytes 0x00..0x1f.
const (
	fixtureClientProof = "BAlJ53Sa5jmYJrxcRsP8IBVCqJKk0T2js4PLO6iz/+4="
	fixtureServerProof = "IXnriMtNXLOrg4OAyMkNDkUtiwcPCBKfiNgNnR/iaz4="
)

func fixtureBinding() []byte {
	b := make([]byte, bindingLen)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestProofFixtures(t *testing.T) {
	if got := ClientProof("pw", fixtureBinding()); got != fixtureClientProof {
		t.Fatalf("client proof drifted: %s", got)
	}
	if got := ServerProof("pw", fixtureBinding()); got != fixtureServerProof {
		t.Fatalf("server proof drifted: %s", got)
	}
	if ClientProof("pw", fixtureBinding()) == ServerProof("pw", fixtureBinding()) {
		t.Fatal("client and server proofs must differ")
	}
	if !VerifyProof(fixtureClientProof, ClientProof("pw", fixtureBinding())) {
		t.Fatal("verify rejected the expected proof")
	}
	if VerifyProof(ClientProof("wrong", fixtureBinding()), fixtureClientProof) {
		t.Fatal("verify accepted a proof under another password")
	}
}

// TestChannelBindingMatchesAcrossTLS13 checks both ends of a TLS 1.3
// connection derive the same binding and that another connection derives a
// different one.
func TestChannelBindingMatchesAcrossTLS13(t *testing.T) {
	cert := selfSigned(t)
	scfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ccfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} // #nosec G402 — test

	connect := func() (server, client []byte) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		done := make(chan []byte, 1)
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				done <- nil
				return
			}
			tc := tls.Server(raw, scfg)
			if err := tc.Handshake(); err != nil {
				done <- nil
				return
			}
			b, _ := ChannelBinding(tc.ConnectionState())
			done <- b
		}()
		tc, err := tls.Dial("tcp", ln.Addr().String(), ccfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tc.Close() }()
		client, err = ChannelBinding(tc.ConnectionState())
		if err != nil {
			t.Fatal(err)
		}
		return <-done, client
	}
	s1, c1 := connect()
	s2, _ := connect()
	if len(s1) != bindingLen || string(s1) != string(c1) {
		t.Fatalf("binding mismatch: server %x client %x", s1, c1)
	}
	if string(s1) == string(s2) {
		t.Fatal("two connections derived the same binding")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
