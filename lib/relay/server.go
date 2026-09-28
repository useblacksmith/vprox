// Package relay is the vprox side of the macOS static-IP egress proxy. A
// host egress proxy opens one TLS 1.3 connection per VM, authenticates
// with a session hello, and multiplexes that VM's TCP and UDP flows over
// yamux streams. The relay dials each destination from the static IP the
// session was granted, enforces the destination policy, and splices.
package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/modal-labs/vprox/lib/relayproto"
)

// Limits bounds what one relay process accepts.
type Limits struct {
	MaxSessions          int
	MaxSessionsPerSource int
	MaxStreamsPerSession int
	MaxUDPPerSession     int
	// StreamWindow is the yamux per-stream receive window.
	StreamWindow uint32
	// AcceptBacklog is the yamux per-session backlog of streams the client
	// may open before the relay has accepted them.
	AcceptBacklog int
	HelloTimeout  time.Duration
	DialTimeout   time.Duration
	TCPIdle       time.Duration
	UDPIdle       time.Duration
	DrainTimeout  time.Duration
}

// DefaultLimits are the production defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxSessions:          4096,
		MaxSessionsPerSource: 64,
		MaxStreamsPerSession: 4096,
		MaxUDPPerSession:     1024,
		StreamWindow:         256 * 1024,
		AcceptBacklog:        256,
		HelloTimeout:         10 * time.Second,
		DialTimeout:          5 * time.Second,
		TCPIdle:              6 * time.Hour,
		UDPIdle:              60 * time.Second,
		DrainTimeout:         15 * time.Second,
	}
}

// Config configures a Server.
type Config struct {
	TLS *tls.Config
	// Password is the shared secret (VPROX_PASSWORD) both ends prove over
	// the TLS channel in the hello; it is never sent on the wire.
	Password string
	// AllowSources restricts which peers may connect; empty allows none.
	AllowSources []netip.Prefix
	Policy       *Policy
	Limits       Limits
	Metrics      *Metrics
	// EgressAddrs overrides the check that a requested static IP is one of
	// this host's addresses (tests). Defaults to Policy.IsOwnAddr.
	EgressAddrs func(netip.Addr) bool
	Logf        func(format string, args ...any)
}

// Server accepts relay sessions.
type Server struct {
	cfg  Config
	ycfg *yamux.Config

	mu        sync.Mutex
	sessions  map[*session]struct{}
	perSource map[netip.Addr]int
	draining  bool

	wg      sync.WaitGroup
	bufPool sync.Pool
}

// NewServer validates cfg and returns a Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.TLS == nil {
		return nil, errors.New("relay: TLS config required")
	}
	if cfg.Password == "" {
		return nil, errors.New("relay: password required")
	}
	if cfg.Policy == nil {
		cfg.Policy = NewPolicy(PolicyConfig{})
	}
	if cfg.Metrics == nil {
		return nil, errors.New("relay: metrics required")
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.EgressAddrs == nil {
		cfg.EgressAddrs = cfg.Policy.IsOwnAddr
	}
	def := DefaultLimits()
	l := &cfg.Limits
	setInt := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	setDur := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	setInt(&l.MaxSessions, def.MaxSessions)
	setInt(&l.MaxSessionsPerSource, def.MaxSessionsPerSource)
	setInt(&l.MaxStreamsPerSession, def.MaxStreamsPerSession)
	setInt(&l.MaxUDPPerSession, def.MaxUDPPerSession)
	setInt(&l.AcceptBacklog, def.AcceptBacklog)
	if l.StreamWindow == 0 {
		l.StreamWindow = def.StreamWindow
	}
	setDur(&l.HelloTimeout, def.HelloTimeout)
	setDur(&l.DialTimeout, def.DialTimeout)
	setDur(&l.TCPIdle, def.TCPIdle)
	setDur(&l.UDPIdle, def.UDPIdle)
	setDur(&l.DrainTimeout, def.DrainTimeout)

	tcfg := cfg.TLS.Clone()
	tcfg.MinVersion = tls.VersionTLS13

	ycfg := yamux.DefaultConfig()
	ycfg.AcceptBacklog = l.AcceptBacklog
	ycfg.MaxStreamWindowSize = l.StreamWindow
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 15 * time.Second
	ycfg.ConnectionWriteTimeout = 30 * time.Second
	ycfg.StreamCloseTimeout = 5 * time.Minute
	ycfg.LogOutput = io.Discard

	s := &Server{
		cfg:       cfg,
		ycfg:      ycfg,
		sessions:  make(map[*session]struct{}),
		perSource: make(map[netip.Addr]int),
	}
	s.cfg.TLS = tcfg
	s.bufPool.New = func() any {
		b := make([]byte, 256*1024)
		return &b
	}
	return s, nil
}

// Serve accepts on ln until ctx is cancelled, then drains: the listener
// closes, every session receives a yamux GoAway so the host proxy
// reconnects to the next relay process, and open streams get up to
// Limits.DrainTimeout to finish before they are cut. A Server serves one
// listener; Serve must not be called concurrently.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- s.acceptLoop(ln)
	}()

	select {
	case err := <-acceptErr:
		return err
	case <-ctx.Done():
	}
	_ = ln.Close()
	<-acceptErr
	s.drain()
	return nil
}

func (s *Server) drain() {
	s.mu.Lock()
	s.draining = true
	sessions := make([]*session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	s.cfg.Metrics.Draining.Set(1)
	s.cfg.Logf("relay: draining %d sessions for up to %s", len(sessions), s.cfg.Limits.DrainTimeout)
	for _, sess := range sessions {
		sess.goAway()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(s.cfg.Limits.DrainTimeout):
		s.cfg.Logf("relay: drain timeout; closing remaining sessions")
		for _, sess := range sessions {
			sess.close()
		}
		<-done
	}
	s.cfg.Logf("relay: drained")
}

func (s *Server) acceptLoop(ln net.Listener) error {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay < time.Second {
				delay *= 2
			}
			s.cfg.Logf("relay: accept: %v (retry in %s)", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		src, ok := remoteAddr(c)
		if !ok || !s.sourceAllowed(src) {
			s.cfg.Metrics.SourceRejected.Inc()
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(c, src)
		}()
	}
}

func remoteAddr(c net.Conn) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

func (s *Server) sourceAllowed(src netip.Addr) bool {
	for _, pfx := range s.cfg.AllowSources {
		if pfx.Contains(src) {
			return true
		}
	}
	return false
}

func (s *Server) handleConn(raw net.Conn, src netip.Addr) {
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	tc := tls.Server(raw, s.cfg.TLS)
	defer tc.Close()

	_ = tc.SetDeadline(time.Now().Add(s.cfg.Limits.HelloTimeout))
	if err := tc.Handshake(); err != nil {
		s.cfg.Logf("relay: %s: tls handshake: %v", src, err)
		return
	}
	hello, err := relayproto.ReadHello(tc)
	if err != nil {
		s.refuseHello(tc, src, relayproto.HelloProtocolError, "malformed hello")
		return
	}
	binding, err := relayproto.ChannelBinding(tc.ConnectionState())
	if err != nil {
		s.refuseHello(tc, src, relayproto.HelloProtocolError, "channel binding unavailable")
		return
	}
	if !relayproto.VerifyProof(hello.Auth, relayproto.ClientProof(s.cfg.Password, binding)) {
		s.refuseHello(tc, src, relayproto.HelloUnauthorized, "bad credential")
		return
	}
	staticIP, err := netip.ParseAddr(hello.StaticIP)
	if err != nil || !staticIP.Is4() || !s.cfg.EgressAddrs(staticIP) {
		s.refuseHello(tc, src, relayproto.HelloBadStaticIP, "static IP is not served by this relay")
		return
	}

	sess := &session{
		srv:      s,
		src:      src,
		vmID:     hello.VMID,
		staticIP: staticIP,
	}
	if status, msg := s.admitSession(sess); status != relayproto.HelloOK {
		s.refuseHello(tc, src, status, msg)
		return
	}
	defer s.releaseSession(sess)

	if err := relayproto.WriteHelloReply(tc, relayproto.HelloOK, relayproto.HelloReplyBody{
		EgressIP: staticIP.String(),
		Proof:    relayproto.ServerProof(s.cfg.Password, binding),
	}); err != nil {
		return
	}
	_ = tc.SetDeadline(time.Time{})

	ys, err := yamux.Server(tc, s.ycfg)
	if err != nil {
		s.cfg.Logf("relay: %s vm=%s: yamux: %v", src, hello.VMID, err)
		return
	}
	sess.setMux(ys)
	s.cfg.Metrics.SessionsTotal.Inc()
	s.cfg.Logf("relay: session open src=%s vm=%s egress=%s", src, hello.VMID, staticIP)
	sess.serve()
	s.cfg.Logf("relay: session closed src=%s vm=%s egress=%s streams=%d bytes_in=%d bytes_out=%d",
		src, hello.VMID, staticIP, sess.streamsTotal.Load(), sess.bytesIn.Load(), sess.bytesOut.Load())
}

func (s *Server) refuseHello(tc *tls.Conn, src netip.Addr, status byte, msg string) {
	s.cfg.Metrics.HelloRefusedTotal.WithLabelValues(relayproto.HelloStatusString(status)).Inc()
	s.cfg.Logf("relay: %s: hello refused: %s", src, relayproto.HelloStatusString(status))
	_ = relayproto.WriteHelloReply(tc, status, relayproto.HelloReplyBody{Error: msg})
}

// admitSession registers sess and returns HelloOK, or the hello status and
// message to refuse it with.
func (s *Server) admitSession(sess *session) (byte, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return relayproto.HelloUnavailable, "relay is draining"
	}
	if len(s.sessions) >= s.cfg.Limits.MaxSessions {
		return relayproto.HelloSessionLimit, "session limit"
	}
	if s.perSource[sess.src] >= s.cfg.Limits.MaxSessionsPerSource {
		return relayproto.HelloSessionLimit, "per-source session limit"
	}
	s.sessions[sess] = struct{}{}
	s.perSource[sess.src]++
	s.cfg.Metrics.SessionsOpen.Set(float64(len(s.sessions)))
	return relayproto.HelloOK, ""
}

func (s *Server) releaseSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sess]; !ok {
		return
	}
	delete(s.sessions, sess)
	if s.perSource[sess.src]--; s.perSource[sess.src] <= 0 {
		delete(s.perSource, sess.src)
	}
	s.cfg.Metrics.SessionsOpen.Set(float64(len(s.sessions)))
}

// Sessions reports the number of open sessions.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// session is one authenticated per-VM yamux session.
type session struct {
	srv      *Server
	src      netip.Addr
	vmID     string
	staticIP netip.Addr

	// The session is registered (and thus reachable by drain) before the
	// hello reply is written and the mux exists, so a GoAway requested in
	// that window is recorded and sent as soon as the mux is set.
	muxMu     sync.Mutex
	mux       *yamux.Session
	goAwaySet bool

	streamsOpen  atomic.Int64
	udpOpen      atomic.Int64
	streamsTotal atomic.Int64
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64

	streamWG sync.WaitGroup
}

func (sess *session) setMux(ys *yamux.Session) {
	sess.muxMu.Lock()
	sess.mux = ys
	pending := sess.goAwaySet
	sess.muxMu.Unlock()
	if pending {
		_ = ys.GoAway()
	}
}

func (sess *session) goAway() {
	sess.muxMu.Lock()
	sess.goAwaySet = true
	mux := sess.mux
	sess.muxMu.Unlock()
	if mux != nil {
		_ = mux.GoAway()
	}
}

func (sess *session) close() {
	sess.muxMu.Lock()
	mux := sess.mux
	sess.muxMu.Unlock()
	if mux != nil {
		_ = mux.Close()
	}
}

func (sess *session) serve() {
	for {
		st, err := sess.mux.AcceptStream()
		if err != nil {
			break
		}
		sess.streamWG.Add(1)
		go func() {
			defer sess.streamWG.Done()
			sess.handleStream(st)
		}()
	}
	_ = sess.mux.Close()
	sess.streamWG.Wait()
}

func (sess *session) handleStream(st *yamux.Stream) {
	defer st.Close()
	srv := sess.srv
	lim := srv.cfg.Limits

	_ = st.SetReadDeadline(time.Now().Add(lim.HelloTimeout))
	hdr, err := relayproto.ReadStreamHeader(st)
	if err != nil {
		sess.refuseStream(st, relayproto.StreamBadHeader)
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	srv.mu.Lock()
	draining := srv.draining
	srv.mu.Unlock()
	if draining {
		sess.refuseStream(st, relayproto.StreamUnavailable)
		return
	}
	if err := srv.cfg.Policy.Check(hdr.Dst); err != nil {
		srv.cfg.Logf("relay: vm=%s: %v", sess.vmID, err)
		sess.refuseStream(st, relayproto.StreamPolicyDenied)
		return
	}
	if sess.streamsOpen.Add(1) > int64(lim.MaxStreamsPerSession) {
		sess.streamsOpen.Add(-1)
		sess.refuseStream(st, relayproto.StreamLimit)
		return
	}
	defer sess.streamsOpen.Add(-1)

	switch hdr.Proto {
	case relayproto.ProtoTCP:
		sess.relayTCP(st, hdr.Dst)
	case relayproto.ProtoUDP:
		if sess.udpOpen.Add(1) > int64(lim.MaxUDPPerSession) {
			sess.udpOpen.Add(-1)
			sess.refuseStream(st, relayproto.StreamUDPLimit)
			return
		}
		defer sess.udpOpen.Add(-1)
		sess.relayUDP(st, hdr.Dst)
	}
}

func (sess *session) refuseStream(st *yamux.Stream, status byte) {
	sess.srv.cfg.Metrics.StreamRefused.WithLabelValues(relayproto.StreamStatusString(status)).Inc()
	_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = st.Write(relayproto.EncodeStreamReply(status))
}

// dialed records a successful destination dial and sends StreamOK. It
// returns false if the reply could not be written; the caller then gives
// up on the stream.
func (sess *session) dialed(st *yamux.Stream, proto string, dial time.Duration) bool {
	m := sess.srv.cfg.Metrics
	m.DialSeconds.WithLabelValues(proto).Observe(dial.Seconds())
	m.StreamsTotal.WithLabelValues(proto).Inc()
	sess.streamsTotal.Add(1)

	_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := st.Write(relayproto.EncodeStreamReply(relayproto.StreamOK)); err != nil {
		return false
	}
	_ = st.SetWriteDeadline(time.Time{})
	return true
}

func (sess *session) relayTCP(st *yamux.Stream, dst netip.AddrPort) {
	srv := sess.srv
	m := srv.cfg.Metrics
	label := sess.staticIP.String()

	d := net.Dialer{
		Timeout:   srv.cfg.Limits.DialTimeout,
		LocalAddr: &net.TCPAddr{IP: sess.staticIP.AsSlice()},
	}
	t0 := time.Now()
	c, err := d.Dial("tcp4", dst.String())
	dial := time.Since(t0)
	if err != nil {
		srv.cfg.Logf("relay: vm=%s: dial %s: %v", sess.vmID, dst, err)
		sess.refuseStream(st, relayproto.StreamDialFailed)
		return
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	_ = tc.SetNoDelay(true)
	m.StreamsOpen.WithLabelValues("tcp").Inc()
	defer m.StreamsOpen.WithLabelValues("tcp").Dec()
	if !sess.dialed(st, "tcp", dial) {
		return
	}

	idle := newIdleGuard(srv.cfg.Limits.TCPIdle, func() {
		_ = tc.Close()
		_ = st.Close()
	})
	defer idle.stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// destination -> guest
		n := sess.copyBuf(st, tc, idle)
		sess.bytesOut.Add(n)
		m.BytesTotal.WithLabelValues("out", label).Add(float64(n))
		// yamux Close sends FIN and still drains reads: half-close.
		_ = st.Close()
	}()
	// guest -> destination
	n := sess.copyBuf(tc, st, idle)
	sess.bytesIn.Add(n)
	m.BytesTotal.WithLabelValues("in", label).Add(float64(n))
	_ = tc.CloseWrite()
	<-done
}

// copyBuf copies src to dst with a pooled buffer and reports activity to
// the idle guard.
func (sess *session) copyBuf(dst io.Writer, src io.Reader, idle *idleGuard) int64 {
	bp := sess.srv.bufPool.Get().(*[]byte)
	defer sess.srv.bufPool.Put(bp)
	buf := *bp
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			idle.touch()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total
			}
			total += int64(n)
		}
		if rerr != nil {
			return total
		}
	}
}

func (sess *session) relayUDP(st *yamux.Stream, dst netip.AddrPort) {
	srv := sess.srv
	m := srv.cfg.Metrics
	label := sess.staticIP.String()

	t0 := time.Now()
	uc, err := net.DialUDP("udp4", &net.UDPAddr{IP: sess.staticIP.AsSlice()}, net.UDPAddrFromAddrPort(dst))
	dial := time.Since(t0)
	if err != nil {
		srv.cfg.Logf("relay: vm=%s: udp %s: %v", sess.vmID, dst, err)
		sess.refuseStream(st, relayproto.StreamDialFailed)
		return
	}
	defer uc.Close()
	m.StreamsOpen.WithLabelValues("udp").Inc()
	defer m.StreamsOpen.WithLabelValues("udp").Dec()
	if !sess.dialed(st, "udp", dial) {
		return
	}

	idle := newIdleGuard(srv.cfg.Limits.UDPIdle, func() {
		_ = uc.Close()
		_ = st.Close()
	})
	defer idle.stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, relayproto.MaxDatagram)
		var total int64
		for {
			// A zero-length datagram is a valid UDP message; forward it.
			n, err := uc.Read(buf)
			if err != nil {
				break
			}
			idle.touch()
			if werr := relayproto.WriteDatagram(st, buf[:n]); werr != nil {
				break
			}
			total += int64(n)
		}
		sess.bytesOut.Add(total)
		m.BytesTotal.WithLabelValues("out", label).Add(float64(total))
		_ = st.Close()
	}()
	buf := make([]byte, relayproto.MaxDatagram)
	var total int64
	for {
		p, err := relayproto.ReadDatagram(st, buf)
		if err != nil {
			break
		}
		idle.touch()
		if _, err := uc.Write(p); err != nil {
			break
		}
		total += int64(len(p))
	}
	sess.bytesIn.Add(total)
	m.BytesTotal.WithLabelValues("in", label).Add(float64(total))
	_ = uc.Close()
	<-done
}

// idleGuard fires onIdle once no touch() happened for the timeout.
type idleGuard struct {
	timeout time.Duration
	last    atomic.Int64
	timer   *time.Timer
	onIdle  func()
}

func newIdleGuard(timeout time.Duration, onIdle func()) *idleGuard {
	g := &idleGuard{timeout: timeout, onIdle: onIdle}
	g.last.Store(time.Now().UnixNano())
	g.timer = time.AfterFunc(timeout, g.check)
	return g
}

func (g *idleGuard) touch() {
	g.last.Store(time.Now().UnixNano())
}

func (g *idleGuard) check() {
	idleFor := time.Since(time.Unix(0, g.last.Load()))
	if idleFor >= g.timeout {
		g.onIdle()
		return
	}
	g.timer.Reset(g.timeout - idleFor)
}

func (g *idleGuard) stop() {
	g.timer.Stop()
}
