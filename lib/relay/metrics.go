package relay

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the relay's Prometheus collectors.
type Metrics struct {
	SessionsOpen      prometheus.Gauge
	SessionsTotal     prometheus.Counter
	HelloRefusedTotal *prometheus.CounterVec
	StreamsOpen       *prometheus.GaugeVec
	StreamsTotal      *prometheus.CounterVec
	StreamRefused     *prometheus.CounterVec
	BytesTotal        *prometheus.CounterVec
	DialSeconds       *prometheus.HistogramVec
	SourceRejected    prometheus.Counter
	Draining          prometheus.Gauge
}

// NewMetrics registers the relay collectors on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		SessionsOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vprox_relay_sessions_open",
			Help: "Authenticated relay sessions currently open.",
		}),
		SessionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vprox_relay_sessions_total",
			Help: "Authenticated relay sessions accepted since start.",
		}),
		HelloRefusedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vprox_relay_hello_refused_total",
			Help: "Session hellos refused, by status.",
		}, []string{"status"}),
		StreamsOpen: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vprox_relay_streams_open",
			Help: "Relayed streams currently open, by proto.",
		}, []string{"proto"}),
		StreamsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vprox_relay_streams_total",
			Help: "Relayed streams accepted since start, by proto.",
		}, []string{"proto"}),
		StreamRefused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vprox_relay_streams_refused_total",
			Help: "Streams refused before splicing, by status.",
		}, []string{"status"}),
		BytesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vprox_relay_bytes_total",
			Help: "Bytes relayed, by direction (in = towards the destination) and static IP.",
		}, []string{"dir", "static_ip"}),
		DialSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "vprox_relay_dial_seconds",
			Help:    "Time to dial the destination from the static IP.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"proto"}),
		SourceRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vprox_relay_source_rejected_total",
			Help: "TCP connections dropped because the source is outside the allow-list.",
		}),
		Draining: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vprox_relay_draining",
			Help: "1 while the relay is draining for shutdown.",
		}),
	}
	reg.MustRegister(m.SessionsOpen, m.SessionsTotal, m.HelloRefusedTotal, m.StreamsOpen,
		m.StreamsTotal, m.StreamRefused, m.BytesTotal, m.DialSeconds, m.SourceRejected, m.Draining)
	return m
}
