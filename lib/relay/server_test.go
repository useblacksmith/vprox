package relay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/modal-labs/vprox/lib/relayproto"
)

func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

type testRelay struct {
	srv    *Server
	addr   string
	cancel context.CancelFunc
	done   chan struct{}
}

func startRelay(t *testing.T, mutate func(*Config)) *testRelay {
	t.Helper()
	reg := prometheus.NewRegistry()
	cfg := Config{
		TLS:          testTLS(t),
		Password:     "pw",
		AllowSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		// Loopback is the only destination available in a unit test, so
		// the deny-list is emptied; TestPolicyTable covers the real one.
		Policy: NewPolicy(PolicyConfig{
			DenyPrefixes: []netip.Prefix{},
			OwnAddrs:     func() ([]netip.Addr, error) { return nil, nil },
		}),
		Metrics:     NewMetrics(reg),
		EgressAddrs: func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") },
		Logf:        t.Logf,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &testRelay{srv: srv, addr: ln.Addr().String(), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		if err := srv.Serve(ctx, ln); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(30 * time.Second):
			t.Error("relay did not stop")
		}
	})
	return r
}

func dialHello(t *testing.T, addr string, body relayproto.HelloBody) (*tls.Conn, byte, relayproto.HelloReplyBody) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := relayproto.WriteHello(tc, body); err != nil {
		t.Fatal(err)
	}
	st, reply, err := relayproto.ReadHelloReply(tc)
	if err != nil {
		t.Fatal(err)
	}
	return tc, st, reply
}

func openSession(t *testing.T, addr string) *yamux.Session {
	t.Helper()
	tc, st, reply := dialHello(t, addr, relayproto.HelloBody{Auth: "pw", VMID: "vm1", StaticIP: "127.0.0.1"})
	if st != relayproto.HelloOK {
		t.Fatalf("hello: %d %+v", st, reply)
	}
	if reply.EgressIP != "127.0.0.1" {
		t.Fatalf("egress ip %q", reply.EgressIP)
	}
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	sess, err := yamux.Client(tc, ycfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func openStream(t *testing.T, sess *yamux.Session, proto byte, dst netip.AddrPort) (*yamux.Stream, byte) {
	t.Helper()
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := relayproto.EncodeStreamHeader(relayproto.StreamHeader{Proto: proto, Dst: dst})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(hdr); err != nil {
		t.Fatal(err)
	}
	status, err := relayproto.ReadStreamReply(st)
	if err != nil {
		t.Fatal(err)
	}
	return st, status
}

func tcpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(buf[:n], from)
		}
	}()
	return netip.MustParseAddrPort(uc.LocalAddr().String())
}

func TestHelloRefusals(t *testing.T) {
	t.Parallel()
	r := startRelay(t, nil)

	_, st, _ := dialHello(t, r.addr, relayproto.HelloBody{Auth: "wrong", StaticIP: "127.0.0.1"})
	if st != relayproto.HelloUnauthorized {
		t.Fatalf("bad password: status %d", st)
	}
	_, st, _ = dialHello(t, r.addr, relayproto.HelloBody{Auth: "pw", StaticIP: "10.9.9.9"})
	if st != relayproto.HelloBadStaticIP {
		t.Fatalf("foreign static ip: status %d", st)
	}
	_, st, _ = dialHello(t, r.addr, relayproto.HelloBody{Auth: "pw", StaticIP: "not-an-ip"})
	if st != relayproto.HelloBadStaticIP {
		t.Fatalf("garbage static ip: status %d", st)
	}

	// Garbage instead of a hello gets a protocol error, not a hang.
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	st, _, err = relayproto.ReadHelloReply(tc)
	if err != nil || st != relayproto.HelloProtocolError {
		t.Fatalf("garbage hello: %d %v", st, err)
	}
	if r.srv.Sessions() != 0 {
		t.Fatalf("refused hellos must not count as sessions: %d", r.srv.Sessions())
	}
}

func TestTCPRelayEcho(t *testing.T) {
	t.Parallel()
	r := startRelay(t, nil)
	echo := tcpEcho(t)
	sess := openSession(t, r.addr)

	st, status := openStream(t, sess, relayproto.ProtoTCP, echo)
	if status != relayproto.StreamOK {
		t.Fatalf("status %d", status)
	}
	payload := bytes.Repeat([]byte("relay-tcp-"), 100_000) // ~1 MB, exceeds the stream window
	go func() {
		_, _ = st.Write(payload)
		_ = st.Close() // half-close: FIN towards the destination
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %d bytes vs %d", len(got), len(payload))
	}
	if r.srv.Sessions() != 1 {
		t.Fatalf("sessions=%d", r.srv.Sessions())
	}
}

func TestTCPDialFailedAndPolicyDenied(t *testing.T) {
	t.Parallel()
	r := startRelay(t, func(c *Config) {
		c.Policy = NewPolicy(PolicyConfig{
			DenyPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")},
			OwnAddrs:     func() ([]netip.Addr, error) { return nil, nil },
		})
		c.Limits.DialTimeout = time.Second
	})
	sess := openSession(t, r.addr)

	// A closed port on loopback refuses fast.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()
	_, status := openStream(t, sess, relayproto.ProtoTCP, closed)
	if status != relayproto.StreamDialFailed {
		t.Fatalf("closed port: status %d", status)
	}
	_, status = openStream(t, sess, relayproto.ProtoTCP, netip.MustParseAddrPort("127.0.0.2:80"))
	if status != relayproto.StreamPolicyDenied {
		t.Fatalf("denied prefix: status %d", status)
	}
	// The session must survive refused streams.
	echo := tcpEcho(t)
	_, status = openStream(t, sess, relayproto.ProtoTCP, echo)
	if status != relayproto.StreamOK {
		t.Fatalf("after refusals: status %d", status)
	}
}

func TestUDPRelayEcho(t *testing.T) {
	t.Parallel()
	r := startRelay(t, nil)
	echo := udpEcho(t)
	sess := openSession(t, r.addr)

	st, status := openStream(t, sess, relayproto.ProtoUDP, echo)
	if status != relayproto.StreamOK {
		t.Fatalf("status %d", status)
	}
	buf := make([]byte, relayproto.MaxDatagram)
	for i, msg := range []string{"ntp-request-1", "", "second"} {
		if err := relayproto.WriteDatagram(st, []byte(msg)); err != nil {
			t.Fatal(err)
		}
		_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := relayproto.ReadDatagram(st, buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("datagram %d: %q != %q", i, got, msg)
		}
	}
}

func TestUDPIdleClosesStream(t *testing.T) {
	t.Parallel()
	r := startRelay(t, func(c *Config) { c.Limits.UDPIdle = 200 * time.Millisecond })
	echo := udpEcho(t)
	sess := openSession(t, r.addr)
	st, status := openStream(t, sess, relayproto.ProtoUDP, echo)
	if status != relayproto.StreamOK {
		t.Fatalf("status %d", status)
	}
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := relayproto.ReadDatagram(st, make([]byte, 16)); err == nil {
		t.Fatal("expected the relay to close the idle UDP stream")
	}
}

func TestStreamLimits(t *testing.T) {
	t.Parallel()
	r := startRelay(t, func(c *Config) {
		c.Limits.MaxStreamsPerSession = 2
		c.Limits.MaxUDPPerSession = 1
	})
	echo := tcpEcho(t)
	uecho := udpEcho(t)
	sess := openSession(t, r.addr)

	s1, status := openStream(t, sess, relayproto.ProtoTCP, echo)
	if status != relayproto.StreamOK {
		t.Fatalf("s1: %d", status)
	}
	_, status = openStream(t, sess, relayproto.ProtoUDP, uecho)
	if status != relayproto.StreamOK {
		t.Fatalf("udp1: %d", status)
	}
	_, status = openStream(t, sess, relayproto.ProtoTCP, echo)
	if status != relayproto.StreamLimit {
		t.Fatalf("over stream limit: %d", status)
	}
	_ = s1.Close()
	// Wait for the relay to release the slot, then a UDP stream must hit
	// the UDP-specific limit rather than the generic one.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, status = openStream(t, sess, relayproto.ProtoUDP, uecho)
		if status == relayproto.StreamUDPLimit || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != relayproto.StreamUDPLimit {
		t.Fatalf("over udp limit: %d", status)
	}
}

func TestSessionLimits(t *testing.T) {
	t.Parallel()
	r := startRelay(t, func(c *Config) { c.Limits.MaxSessionsPerSource = 1 })
	openSession(t, r.addr)
	_, st, _ := dialHello(t, r.addr, relayproto.HelloBody{Auth: "pw", StaticIP: "127.0.0.1"})
	if st != relayproto.HelloSessionLimit {
		t.Fatalf("second session from the same source: %d", st)
	}
}

func TestSourceAllowlist(t *testing.T) {
	t.Parallel()
	r := startRelay(t, func(c *Config) {
		c.AllowSources = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	})
	raw, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake from a disallowed source must fail")
	}
}

func TestDrainSendsGoAwayAndWaitsForStreams(t *testing.T) {
	t.Parallel()
	r := startRelay(t, func(c *Config) { c.Limits.DrainTimeout = 5 * time.Second })
	echo := tcpEcho(t)
	sess := openSession(t, r.addr)
	st, status := openStream(t, sess, relayproto.ProtoTCP, echo)
	if status != relayproto.StreamOK {
		t.Fatalf("status %d", status)
	}

	r.cancel()
	// GoAway: the client can no longer open streams...
	deadline := time.Now().Add(5 * time.Second)
	for {
		extra, err := sess.OpenStream()
		if err != nil {
			break
		}
		_ = extra.Close()
		if time.Now().After(deadline) {
			t.Fatal("expected OpenStream to fail after GoAway")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// ...but the in-flight stream keeps working until it finishes.
	if _, err := st.Write([]byte("still-here")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 10)
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "still-here" {
		t.Fatalf("in-flight stream after drain start: %q %v", buf, err)
	}
	select {
	case <-r.done:
		t.Fatal("relay exited while a stream was still open")
	case <-time.After(300 * time.Millisecond):
	}
	_ = st.Close()
	_ = sess.Close()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not exit once streams drained")
	}
}
