// Package relayproto is the wire protocol between the macOS host egress
// proxy and the vprox relay. It is deliberately small and binary so both
// sides (FastActions/fa agent/egressproxy/relayproto and this package) can
// carry an identical copy verified by shared hex fixtures.
//
// Protocol v1, all integers big-endian:
//
//	TLS 1.3 connection
//	  client -> server  Hello:      "BRLY" | u8 version=1 | u16 len | JSON HelloBody
//	  server -> client  HelloReply: u8 status | u16 len | JSON HelloReplyBody
//	  then the connection carries a yamux session (client side opens streams)
//
//	per yamux stream
//	  client -> server  StreamHeader: u8 proto (6=TCP, 17=UDP) | 4 bytes dst IPv4 | u16 dst port
//	  server -> client  StreamReply:  u8 status | u32 dial micros
//	  TCP: raw bytes both ways, half-close propagated
//	  UDP: datagrams framed as u16 length | payload, both ways
package relayproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// Version is the protocol version carried in the hello.
const Version byte = 1

// Magic is the first four bytes on the wire after the TLS handshake.
var Magic = [4]byte{'B', 'R', 'L', 'Y'}

const (
	ProtoTCP byte = 6
	ProtoUDP byte = 17

	// MaxHelloBody bounds the JSON hello so an unauthenticated peer cannot
	// make the server buffer arbitrary data.
	MaxHelloBody = 4096

	StreamHeaderLen = 7
	StreamReplyLen  = 5

	// MaxDatagram is the largest UDP payload carried in one frame.
	MaxDatagram = 65535
)

// Hello statuses.
const (
	HelloOK            byte = 0
	HelloUnauthorized  byte = 1
	HelloBadStaticIP   byte = 2
	HelloSessionLimit  byte = 3
	HelloProtocolError byte = 4
	HelloUnavailable   byte = 5
)

// Stream statuses.
const (
	StreamOK           byte = 0
	StreamDialFailed   byte = 1
	StreamPolicyDenied byte = 2
	StreamLimit        byte = 3
	StreamUDPLimit     byte = 4
	StreamBadHeader    byte = 5
	StreamUnavailable  byte = 6
)

// HelloStatusString names a hello status for logs and metrics labels.
func HelloStatusString(s byte) string {
	switch s {
	case HelloOK:
		return "ok"
	case HelloUnauthorized:
		return "unauthorized"
	case HelloBadStaticIP:
		return "bad_static_ip"
	case HelloSessionLimit:
		return "session_limit"
	case HelloProtocolError:
		return "protocol_error"
	case HelloUnavailable:
		return "unavailable"
	}
	return fmt.Sprintf("unknown_%d", s)
}

// StreamStatusString names a stream status for logs and metrics labels.
func StreamStatusString(s byte) string {
	switch s {
	case StreamOK:
		return "ok"
	case StreamDialFailed:
		return "dial_failed"
	case StreamPolicyDenied:
		return "policy_denied"
	case StreamLimit:
		return "stream_limit"
	case StreamUDPLimit:
		return "udp_limit"
	case StreamBadHeader:
		return "bad_header"
	case StreamUnavailable:
		return "unavailable"
	}
	return fmt.Sprintf("unknown_%d", s)
}

// HelloBody is the JSON payload of the client hello.
type HelloBody struct {
	// Auth is the bearer credential (phase 1: VPROX_PASSWORD).
	Auth string `json:"auth"`
	// VMID identifies the VM the session belongs to; logged, never trusted
	// for authorization.
	VMID string `json:"vm_id"`
	// StaticIP is the egress address the client requests; must be one of
	// the relay's own addresses.
	StaticIP string `json:"static_ip"`
}

// HelloReplyBody is the JSON payload of the server's hello reply.
type HelloReplyBody struct {
	EgressIP string `json:"egress_ip,omitempty"`
	Error    string `json:"error,omitempty"`
}

// StreamHeader identifies the destination of one stream.
type StreamHeader struct {
	Proto byte
	Dst   netip.AddrPort
}

var (
	ErrBadMagic     = errors.New("relayproto: bad magic")
	ErrBadVersion   = errors.New("relayproto: unsupported version")
	ErrHelloTooBig  = errors.New("relayproto: hello body too large")
	ErrNotIPv4      = errors.New("relayproto: IPv4 destination required")
	ErrBadProto     = errors.New("relayproto: unsupported stream proto")
	ErrDatagramSize = errors.New("relayproto: datagram exceeds 65535 bytes")
)

// WriteHello encodes and writes the client hello.
func WriteHello(w io.Writer, body HelloBody) error {
	b, err := EncodeHello(body)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// EncodeHello encodes the client hello into one frame.
func EncodeHello(body HelloBody) ([]byte, error) {
	js, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(js) > MaxHelloBody {
		return nil, ErrHelloTooBig
	}
	out := make([]byte, 0, 4+1+2+len(js))
	out = append(out, Magic[:]...)
	out = append(out, Version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(js)))
	out = append(out, js...)
	return out, nil
}

// ReadHello reads and decodes the client hello. A bad magic or version is
// reported as ErrBadMagic / ErrBadVersion so the server can answer
// HelloProtocolError.
func ReadHello(r io.Reader) (HelloBody, error) {
	var fixed [7]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return HelloBody{}, err
	}
	if [4]byte(fixed[:4]) != Magic {
		return HelloBody{}, ErrBadMagic
	}
	if fixed[4] != Version {
		return HelloBody{}, ErrBadVersion
	}
	n := int(binary.BigEndian.Uint16(fixed[5:7]))
	if n > MaxHelloBody {
		return HelloBody{}, ErrHelloTooBig
	}
	js := make([]byte, n)
	if _, err := io.ReadFull(r, js); err != nil {
		return HelloBody{}, err
	}
	var body HelloBody
	if err := json.Unmarshal(js, &body); err != nil {
		return HelloBody{}, fmt.Errorf("relayproto: hello body: %w", err)
	}
	return body, nil
}

// EncodeHelloReply encodes the server's answer to the hello.
func EncodeHelloReply(status byte, body HelloReplyBody) ([]byte, error) {
	js, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(js) > MaxHelloBody {
		return nil, ErrHelloTooBig
	}
	out := make([]byte, 0, 1+2+len(js))
	out = append(out, status)
	out = binary.BigEndian.AppendUint16(out, uint16(len(js)))
	out = append(out, js...)
	return out, nil
}

// WriteHelloReply encodes and writes the server's answer to the hello.
func WriteHelloReply(w io.Writer, status byte, body HelloReplyBody) error {
	b, err := EncodeHelloReply(status, body)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadHelloReply reads the server's answer to the hello.
func ReadHelloReply(r io.Reader) (byte, HelloReplyBody, error) {
	var fixed [3]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return 0, HelloReplyBody{}, err
	}
	n := int(binary.BigEndian.Uint16(fixed[1:3]))
	if n > MaxHelloBody {
		return 0, HelloReplyBody{}, ErrHelloTooBig
	}
	js := make([]byte, n)
	if _, err := io.ReadFull(r, js); err != nil {
		return 0, HelloReplyBody{}, err
	}
	var body HelloReplyBody
	if err := json.Unmarshal(js, &body); err != nil {
		return 0, HelloReplyBody{}, fmt.Errorf("relayproto: hello reply body: %w", err)
	}
	return fixed[0], body, nil
}

// EncodeStreamHeader encodes a stream header (IPv4 destinations only).
func EncodeStreamHeader(h StreamHeader) ([]byte, error) {
	if h.Proto != ProtoTCP && h.Proto != ProtoUDP {
		return nil, ErrBadProto
	}
	if !h.Dst.Addr().Is4() {
		return nil, ErrNotIPv4
	}
	out := make([]byte, StreamHeaderLen)
	out[0] = h.Proto
	ip4 := h.Dst.Addr().As4()
	copy(out[1:5], ip4[:])
	binary.BigEndian.PutUint16(out[5:7], h.Dst.Port())
	return out, nil
}

// ReadStreamHeader reads a stream header.
func ReadStreamHeader(r io.Reader) (StreamHeader, error) {
	var b [StreamHeaderLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return StreamHeader{}, err
	}
	if b[0] != ProtoTCP && b[0] != ProtoUDP {
		return StreamHeader{}, ErrBadProto
	}
	addr := netip.AddrFrom4([4]byte(b[1:5]))
	return StreamHeader{Proto: b[0], Dst: netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[5:7]))}, nil
}

// EncodeStreamReply encodes the relay's per-stream answer. The dial time is
// saturated to fit 32 bits of microseconds.
func EncodeStreamReply(status byte, dial time.Duration) []byte {
	out := make([]byte, StreamReplyLen)
	out[0] = status
	us := dial.Microseconds()
	if us < 0 {
		us = 0
	}
	if us > int64(^uint32(0)) {
		us = int64(^uint32(0))
	}
	binary.BigEndian.PutUint32(out[1:], uint32(us))
	return out
}

// ReadStreamReply reads the relay's per-stream answer.
func ReadStreamReply(r io.Reader) (status byte, dial time.Duration, err error) {
	var b [StreamReplyLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, 0, err
	}
	return b[0], time.Duration(binary.BigEndian.Uint32(b[1:])) * time.Microsecond, nil
}

// WriteDatagram writes one length-prefixed UDP payload.
func WriteDatagram(w io.Writer, payload []byte) error {
	if len(payload) > MaxDatagram {
		return ErrDatagramSize
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	copy(buf[2:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadDatagram reads one length-prefixed UDP payload into buf, which must
// hold MaxDatagram bytes, and returns the payload slice.
func ReadDatagram(r io.Reader, buf []byte) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return nil, ErrDatagramSize
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}
