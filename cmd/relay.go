package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"

	"github.com/modal-labs/vprox/lib"
	"github.com/modal-labs/vprox/lib/relay"
)

var RelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Start the static-IP egress relay for macOS hosts (TLS 1.3 + yamux)",
	Long: `Start the egress relay. A macOS host's egress proxy opens one TLS 1.3
session per VM, authenticates with VPROX_PASSWORD, and multiplexes that VM's
TCP and UDP flows over it. The relay dials each destination from the static
IP the session was granted, after checking it against the destination policy.`,
	RunE: runRelay,
}

var relayCmdArgs struct {
	listen        string
	allowSources  []string
	denyCIDRs     []string
	denyPorts     []uint
	tlsCert       string
	tlsKey        string
	metricsAddr   string
	maxSessions   int
	maxPerSource  int
	maxStreams    int
	maxUDP        int
	streamWindow  uint32
	acceptBacklog int
	dialTimeout   time.Duration
	tcpIdle       time.Duration
	udpIdle       time.Duration
	drainTimeout  time.Duration
}

func init() {
	f := RelayCmd.Flags()
	def := relay.DefaultLimits()
	f.StringVar(&relayCmdArgs.listen, "listen", "0.0.0.0:9443",
		"address to accept relay sessions on")
	f.StringArrayVar(&relayCmdArgs.allowSources, "allow-source", nil,
		"source CIDR allowed to open sessions (repeatable, required)")
	f.StringArrayVar(&relayCmdArgs.denyCIDRs, "deny-cidr", nil,
		"destination CIDR to refuse in addition to the built-in list (repeatable)")
	f.UintSliceVar(&relayCmdArgs.denyPorts, "deny-port", nil,
		"destination port to refuse (repeatable)")
	f.StringVar(&relayCmdArgs.tlsCert, "tls-cert", "", "TLS certificate PEM (default: embedded)")
	f.StringVar(&relayCmdArgs.tlsKey, "tls-key", "", "TLS key PEM (default: embedded)")
	f.StringVar(&relayCmdArgs.metricsAddr, "metrics-addr", "127.0.0.1:9444",
		"address for the Prometheus /metrics endpoint (empty disables)")
	f.IntVar(&relayCmdArgs.maxSessions, "max-sessions", def.MaxSessions, "max concurrent sessions")
	f.IntVar(&relayCmdArgs.maxPerSource, "max-sessions-per-source", def.MaxSessionsPerSource,
		"max concurrent sessions per source IP")
	f.IntVar(&relayCmdArgs.maxStreams, "max-streams-per-session", def.MaxStreamsPerSession,
		"max concurrent streams (TCP+UDP) per session")
	f.IntVar(&relayCmdArgs.maxUDP, "max-udp-per-session", def.MaxUDPPerSession,
		"max concurrent UDP flows per session")
	f.Uint32Var(&relayCmdArgs.streamWindow, "stream-window", def.StreamWindow,
		"yamux per-stream receive window in bytes")
	f.IntVar(&relayCmdArgs.acceptBacklog, "accept-backlog", def.AcceptBacklog,
		"yamux per-session stream accept backlog")
	f.DurationVar(&relayCmdArgs.dialTimeout, "dial-timeout", def.DialTimeout, "destination dial timeout")
	f.DurationVar(&relayCmdArgs.tcpIdle, "tcp-idle", def.TCPIdle, "idle timeout for TCP streams")
	f.DurationVar(&relayCmdArgs.udpIdle, "udp-idle", def.UDPIdle, "idle timeout for UDP flows")
	f.DurationVar(&relayCmdArgs.drainTimeout, "drain-timeout", def.DrainTimeout,
		"how long open streams may finish after SIGTERM before they are cut")
}

func runRelay(cmd *cobra.Command, args []string) error {
	var cert tls.Certificate
	var err error
	if relayCmdArgs.tlsCert != "" || relayCmdArgs.tlsKey != "" {
		if relayCmdArgs.tlsCert == "" || relayCmdArgs.tlsKey == "" {
			return errors.New("--tls-cert and --tls-key must be set together")
		}
		cert, err = tls.LoadX509KeyPair(relayCmdArgs.tlsCert, relayCmdArgs.tlsKey)
	} else {
		cert, err = lib.LoadServerTLS()
	}
	if err != nil {
		return err
	}
	if len(relayCmdArgs.allowSources) == 0 {
		return errors.New("missing required flag: --allow-source")
	}
	allow, err := parsePrefixes(relayCmdArgs.allowSources)
	if err != nil {
		return fmt.Errorf("--allow-source: %v", err)
	}
	deny, err := parsePrefixes(relayCmdArgs.denyCIDRs)
	if err != nil {
		return fmt.Errorf("--deny-cidr: %v", err)
	}
	password, err := lib.GetVproxPassword()
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	denyPorts := make([]uint16, 0, len(relayCmdArgs.denyPorts))
	for _, p := range relayCmdArgs.denyPorts {
		if p == 0 || p > 65535 {
			return fmt.Errorf("--deny-port: invalid port %d", p)
		}
		denyPorts = append(denyPorts, uint16(p))
	}
	policy := relay.NewPolicy(relay.PolicyConfig{
		ExtraDenyPrefixes: deny,
		DenyPorts:         denyPorts,
	})
	srv, err := relay.NewServer(relay.Config{
		TLS:          &tls.Config{Certificates: []tls.Certificate{cert}},
		Password:     password,
		AllowSources: allow,
		Policy:       policy,
		Metrics:      relay.NewMetrics(reg),
		Limits: relay.Limits{
			MaxSessions:          relayCmdArgs.maxSessions,
			MaxSessionsPerSource: relayCmdArgs.maxPerSource,
			MaxStreamsPerSession: relayCmdArgs.maxStreams,
			MaxUDPPerSession:     relayCmdArgs.maxUDP,
			StreamWindow:         relayCmdArgs.streamWindow,
			AcceptBacklog:        relayCmdArgs.acceptBacklog,
			DialTimeout:          relayCmdArgs.dialTimeout,
			TCPIdle:              relayCmdArgs.tcpIdle,
			UDPIdle:              relayCmdArgs.udpIdle,
			DrainTimeout:         relayCmdArgs.drainTimeout,
		},
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if relayCmdArgs.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		ms := &http.Server{Addr: relayCmdArgs.metricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("relay: metrics server: %v", err)
			}
		}()
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = ms.Shutdown(shutdownCtx)
		}()
	}

	log.Printf("relay: allow sources %v; deny %s", allow, policy)

	ln, err := net.Listen("tcp", relayCmdArgs.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %v", relayCmdArgs.listen, err)
	}
	log.Printf("relay: listening on %s", ln.Addr())
	return srv.Serve(ctx, ln)
}

func parsePrefixes(strs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(strs))
	for _, s := range strs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
