package relayproto

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/netip"
	"testing"
)

// Wire fixtures shared verbatim with the FastActions/fa copy of this
// package; a change here must be mirrored there (and is a protocol bump).
const (
	fixtureHello       = "42524c5901003f7b2261757468223a22736563726574222c22766d5f6964223a223031414258222c227374617469635f6970223a223230352e3233342e3230302e323437227d"
	fixtureHelloReply  = "00001f7b226567726573735f6970223a223230352e3233342e3230302e323437227d"
	fixtureHelloRefuse = "01001a7b226572726f72223a226261642063726564656e7469616c227d"
	fixtureTCPHeader   = "06010101010050"
	fixtureUDPHeader   = "1101000001007b"
	fixtureReplyOK     = "00"
	fixtureReplyDenied = "02"
	fixtureDatagram    = "0003616263"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHelloFixture(t *testing.T) {
	body := HelloBody{Auth: "secret", VMID: "01ABX", StaticIP: "205.234.200.247"}
	got, err := EncodeHello(body)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, fixtureHello); !bytes.Equal(got, want) {
		t.Fatalf("hello encoding drifted:\n got %x\nwant %x", got, want)
	}
	back, err := ReadHello(bytes.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	if back != body {
		t.Fatalf("round trip: %+v != %+v", back, body)
	}
}

func TestHelloReplyFixtures(t *testing.T) {
	ok, err := EncodeHelloReply(HelloOK, HelloReplyBody{EgressIP: "205.234.200.247"})
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, fixtureHelloReply); !bytes.Equal(ok, want) {
		t.Fatalf("reply encoding drifted:\n got %x\nwant %x", ok, want)
	}
	refuse, err := EncodeHelloReply(HelloUnauthorized, HelloReplyBody{Error: "bad credential"})
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, fixtureHelloRefuse); !bytes.Equal(refuse, want) {
		t.Fatalf("refusal encoding drifted:\n got %x\nwant %x", refuse, want)
	}
	st, body, err := ReadHelloReply(bytes.NewReader(refuse))
	if err != nil {
		t.Fatal(err)
	}
	if st != HelloUnauthorized || body.Error != "bad credential" {
		t.Fatalf("got %d %+v", st, body)
	}
}

func TestHelloRejectsBadMagicAndVersion(t *testing.T) {
	good := mustHex(t, fixtureHello)
	bad := append([]byte{}, good...)
	bad[0] = 'X'
	if _, err := ReadHello(bytes.NewReader(bad)); err != ErrBadMagic {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
	bad = append([]byte{}, good...)
	bad[4] = 2
	if _, err := ReadHello(bytes.NewReader(bad)); err != ErrBadVersion {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
	// Oversized length must be refused before any body is read.
	huge := append([]byte{}, good[:5]...)
	huge = append(huge, 0xff, 0xff)
	if _, err := ReadHello(bytes.NewReader(huge)); err != ErrHelloTooBig {
		t.Fatalf("want ErrHelloTooBig, got %v", err)
	}
}

func TestStreamHeaderFixtures(t *testing.T) {
	cases := []struct {
		h   StreamHeader
		hex string
	}{
		{StreamHeader{Proto: ProtoTCP, Dst: netip.MustParseAddrPort("1.1.1.1:80")}, fixtureTCPHeader},
		{StreamHeader{Proto: ProtoUDP, Dst: netip.MustParseAddrPort("1.0.0.1:123")}, fixtureUDPHeader},
	}
	for _, c := range cases {
		got, err := EncodeStreamHeader(c.h)
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex(t, c.hex); !bytes.Equal(got, want) {
			t.Fatalf("header drifted: got %x want %x", got, want)
		}
		back, err := ReadStreamHeader(bytes.NewReader(got))
		if err != nil {
			t.Fatal(err)
		}
		if back != c.h {
			t.Fatalf("round trip %+v != %+v", back, c.h)
		}
	}
	if _, err := EncodeStreamHeader(StreamHeader{Proto: 1, Dst: netip.MustParseAddrPort("1.1.1.1:1")}); err != ErrBadProto {
		t.Fatalf("want ErrBadProto, got %v", err)
	}
	if _, err := EncodeStreamHeader(StreamHeader{Proto: ProtoTCP, Dst: netip.MustParseAddrPort("[::1]:1")}); err != ErrNotIPv4 {
		t.Fatalf("want ErrNotIPv4, got %v", err)
	}
	if _, err := ReadStreamHeader(bytes.NewReader([]byte{0x02, 1, 1, 1, 1, 0, 80})); err != ErrBadProto {
		t.Fatalf("want ErrBadProto, got %v", err)
	}
}

func TestStreamReplyFixtures(t *testing.T) {
	if got := EncodeStreamReply(StreamOK); !bytes.Equal(got, mustHex(t, fixtureReplyOK)) {
		t.Fatalf("reply drifted: %x", got)
	}
	if got := EncodeStreamReply(StreamPolicyDenied); !bytes.Equal(got, mustHex(t, fixtureReplyDenied)) {
		t.Fatalf("reply drifted: %x", got)
	}
	st, err := ReadStreamReply(bytes.NewReader(mustHex(t, fixtureReplyOK)))
	if err != nil || st != StreamOK {
		t.Fatalf("got %d %v", st, err)
	}
}

func TestDatagramFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDatagram(&buf, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), mustHex(t, fixtureDatagram)) {
		t.Fatalf("datagram drifted: %x", buf.Bytes())
	}
	if err := WriteDatagram(&buf, []byte{}); err != nil {
		t.Fatal(err)
	}
	scratch := make([]byte, MaxDatagram)
	p, err := ReadDatagram(&buf, scratch)
	if err != nil || string(p) != "abc" {
		t.Fatalf("got %q %v", p, err)
	}
	p, err = ReadDatagram(&buf, scratch)
	if err != nil || len(p) != 0 {
		t.Fatalf("empty datagram: %q %v", p, err)
	}
	if _, err := ReadDatagram(&buf, scratch); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
	if err := WriteDatagram(io.Discard, make([]byte, MaxDatagram+1)); err != ErrDatagramSize {
		t.Fatalf("want ErrDatagramSize, got %v", err)
	}
	// A frame larger than the caller's buffer is refused, not truncated.
	if _, err := ReadDatagram(bytes.NewReader([]byte{0x00, 0x05, 1, 2, 3, 4, 5}), make([]byte, 4)); err != ErrDatagramSize {
		t.Fatalf("want ErrDatagramSize, got %v", err)
	}
}
