package lib

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	readinessCheckInterval = 30 * time.Second
	readinessStaleAfter    = 75 * time.Second
	readinessFailureLimit  = 3
	readinessRecoveryLimit = 2
)

// ReadinessStatus describes whether a server should receive new connections.
type ReadinessStatus string

const (
	ReadinessStarting  ReadinessStatus = "starting"
	ReadinessHealthy   ReadinessStatus = "healthy"
	ReadinessDegraded  ReadinessStatus = "degraded"
	ReadinessUnhealthy ReadinessStatus = "unhealthy"
	ReadinessStale     ReadinessStatus = "stale"
)

// ReadinessReason is a stable, low-cardinality explanation for an unhealthy
// readiness check. Detailed errors are logged locally instead of being sent in
// heartbeats.
type ReadinessReason string

const (
	ReadinessReasonStarting              ReadinessReason = "starting"
	ReadinessReasonRecovering            ReadinessReason = "recovering"
	ReadinessReasonListenerUnavailable   ReadinessReason = "listener_unavailable"
	ReadinessReasonWireGuardUnavailable  ReadinessReason = "wireguard_unavailable"
	ReadinessReasonBindInterfaceInvalid  ReadinessReason = "bind_interface_invalid"
	ReadinessReasonBindAddressMissing    ReadinessReason = "bind_address_missing"
	ReadinessReasonDefaultRouteInvalid   ReadinessReason = "default_route_invalid"
	ReadinessReasonForwardingDisabled    ReadinessReason = "ipv4_forwarding_disabled"
	ReadinessReasonIptablesRuleMissing   ReadinessReason = "iptables_rule_missing"
	ReadinessReasonPeerCapacityExhausted ReadinessReason = "peer_capacity_exhausted"
	ReadinessReasonCheckStale            ReadinessReason = "readiness_check_stale"
	ReadinessReasonServerSetupFailed     ReadinessReason = "server_setup_failed"
)

// ReadinessSnapshot is the cached result exposed by the backend heartbeat. It
// deliberately contains no raw system error strings.
type ReadinessSnapshot struct {
	Status              ReadinessStatus `json:"status"`
	Reason              ReadinessReason `json:"reason,omitempty"`
	CheckedAt           *time.Time      `json:"checked_at,omitempty"`
	LastSuccessAt       *time.Time      `json:"last_success_at,omitempty"`
	CheckDurationMillis int64           `json:"check_duration_ms,omitempty"`
	ConsecutiveFailures int             `json:"consecutive_failures"`
}

type readinessTracker struct {
	mu                   sync.RWMutex
	snapshot             ReadinessSnapshot
	startedAt            time.Time
	staleAfter           time.Duration
	consecutiveSuccesses int
}

func newReadinessTracker(now time.Time, staleAfter time.Duration) *readinessTracker {
	return &readinessTracker{
		snapshot: ReadinessSnapshot{
			Status: ReadinessStarting,
			Reason: ReadinessReasonStarting,
		},
		startedAt:  now,
		staleAfter: staleAfter,
	}
}

func (t *readinessTracker) recordSuccess(now time.Time, duration time.Duration) ReadinessSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	previousStatus := t.effectiveStatusLocked(now)
	hadSucceeded := t.snapshot.LastSuccessAt != nil
	if previousStatus == ReadinessStale {
		t.consecutiveSuccesses = 0
	}
	t.consecutiveSuccesses++
	t.snapshot.CheckedAt = timePointer(now)
	t.snapshot.LastSuccessAt = timePointer(now)
	t.snapshot.CheckDurationMillis = duration.Milliseconds()
	t.snapshot.ConsecutiveFailures = 0

	switch {
	case previousStatus == ReadinessStarting && !hadSucceeded:
		t.snapshot.Status = ReadinessHealthy
		t.snapshot.Reason = ""
	case previousStatus == ReadinessHealthy:
		t.snapshot.Reason = ""
	case t.consecutiveSuccesses >= readinessRecoveryLimit:
		t.snapshot.Status = ReadinessHealthy
		t.snapshot.Reason = ""
	case previousStatus == ReadinessUnhealthy || previousStatus == ReadinessStale:
		t.snapshot.Status = ReadinessUnhealthy
		t.snapshot.Reason = ReadinessReasonRecovering
	default:
		t.snapshot.Status = ReadinessDegraded
		t.snapshot.Reason = ReadinessReasonRecovering
	}

	return t.snapshot
}

func (t *readinessTracker) recordFailure(now time.Time, duration time.Duration, reason ReadinessReason) ReadinessSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	previousStatus := t.effectiveStatusLocked(now)
	t.consecutiveSuccesses = 0
	t.snapshot.CheckedAt = timePointer(now)
	t.snapshot.CheckDurationMillis = duration.Milliseconds()
	t.snapshot.ConsecutiveFailures++
	t.snapshot.Reason = reason

	if previousStatus == ReadinessUnhealthy || previousStatus == ReadinessStale ||
		t.snapshot.ConsecutiveFailures >= readinessFailureLimit {
		t.snapshot.Status = ReadinessUnhealthy
	} else if t.snapshot.LastSuccessAt == nil {
		// Do not advertise readiness until at least one full check has passed.
		t.snapshot.Status = ReadinessStarting
	} else {
		t.snapshot.Status = ReadinessDegraded
	}

	return t.snapshot
}

func (t *readinessTracker) recordFatal(now time.Time, reason ReadinessReason) ReadinessSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutiveSuccesses = 0
	t.snapshot.CheckedAt = timePointer(now)
	t.snapshot.CheckDurationMillis = 0
	t.snapshot.ConsecutiveFailures = readinessFailureLimit
	t.snapshot.Status = ReadinessUnhealthy
	t.snapshot.Reason = reason
	return t.snapshot
}

func (t *readinessTracker) get(now time.Time) ReadinessSnapshot {
	t.mu.RLock()
	snapshot := t.snapshot
	startedAt := t.startedAt
	staleAfter := t.staleAfter
	t.mu.RUnlock()

	lastCheck := startedAt
	if snapshot.CheckedAt != nil {
		lastCheck = *snapshot.CheckedAt
	}
	if now.Sub(lastCheck) > staleAfter {
		snapshot.Status = ReadinessStale
		snapshot.Reason = ReadinessReasonCheckStale
	}
	return snapshot
}

func (t *readinessTracker) effectiveStatusLocked(now time.Time) ReadinessStatus {
	lastCheck := t.startedAt
	if t.snapshot.CheckedAt != nil {
		lastCheck = *t.snapshot.CheckedAt
	}
	if now.Sub(lastCheck) > t.staleAfter {
		return ReadinessStale
	}
	return t.snapshot.Status
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

type serverReadiness struct {
	listenerReady atomic.Bool
	tracker       *readinessTracker
}

func (srv *Server) initReadiness() {
	srv.readiness = &serverReadiness{
		tracker: newReadinessTracker(time.Now(), readinessStaleAfter),
	}
}

// Readiness returns the latest cached readiness result. It never inspects or
// mutates host networking.
func (srv *Server) Readiness() ReadinessSnapshot {
	if srv.readiness == nil {
		return ReadinessSnapshot{Status: ReadinessStarting, Reason: ReadinessReasonStarting}
	}
	return srv.readiness.tracker.get(time.Now())
}

func (srv *Server) markReadinessFatal(reason ReadinessReason) {
	if srv.readiness == nil {
		srv.initReadiness()
	}
	srv.readiness.tracker.recordFatal(time.Now(), reason)
}

type readinessCheck struct {
	reason ReadinessReason
	check  func() error
}

func runReadinessChecks(checks []readinessCheck) (ReadinessReason, error) {
	for _, check := range checks {
		if err := check.check(); err != nil {
			return check.reason, err
		}
	}
	return "", nil
}

func (srv *Server) readinessChecks() []readinessCheck {
	return []readinessCheck{
		{ReadinessReasonListenerUnavailable, srv.checkListener},
		{ReadinessReasonWireGuardUnavailable, srv.checkWireGuard},
		{ReadinessReasonBindInterfaceInvalid, srv.checkBindInterface},
		{ReadinessReasonBindAddressMissing, srv.checkBindAddress},
		{ReadinessReasonDefaultRouteInvalid, srv.checkDefaultRoute},
		{ReadinessReasonForwardingDisabled, checkIPv4Forwarding},
		{ReadinessReasonIptablesRuleMissing, srv.checkIptablesRules},
		{ReadinessReasonPeerCapacityExhausted, srv.checkPeerCapacity},
	}
}

func (srv *Server) startReadinessChecks() {
	go func() {
		ticker := time.NewTicker(readinessCheckInterval)
		defer ticker.Stop()

		for {
			srv.runReadinessCheck()
			select {
			case <-srv.Ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (srv *Server) runReadinessCheck() {
	startedAt := time.Now()
	previous := srv.Readiness()
	reason, err := runReadinessChecks(srv.readinessChecks())
	now := time.Now()

	var current ReadinessSnapshot
	if err == nil {
		current = srv.readiness.tracker.recordSuccess(now, now.Sub(startedAt))
	} else {
		current = srv.readiness.tracker.recordFailure(now, now.Sub(startedAt), reason)
	}

	if current.Status != previous.Status || current.Reason != previous.Reason {
		if err != nil {
			log.Printf("[%v] readiness is %s (%s): %v", srv.BindAddr, current.Status, current.Reason, err)
		} else {
			log.Printf("[%v] readiness is %s", srv.BindAddr, current.Status)
		}
	}
}

func (srv *Server) checkListener() error {
	if srv.readiness == nil || !srv.readiness.listenerReady.Load() {
		return fmt.Errorf("HTTPS listener is not active")
	}
	return nil
}

func (srv *Server) checkWireGuard() error {
	link, err := netlink.LinkByName(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to find %s: %v", srv.Ifname(), err)
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("%s is a %s interface", srv.Ifname(), link.Type())
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("%s is down", srv.Ifname())
	}
	if !srv.canAdoptLink(link) {
		return fmt.Errorf("%s does not have the expected WireGuard address %s", srv.Ifname(), srv.WgCidr)
	}
	if srv.WgClient == nil {
		return fmt.Errorf("WireGuard client is unavailable")
	}
	device, err := srv.WgClient.Device(srv.Ifname())
	if err != nil {
		return fmt.Errorf("failed to query %s: %v", srv.Ifname(), err)
	}
	if device.PublicKey != srv.Key.PublicKey() {
		return fmt.Errorf("%s has the wrong WireGuard key", srv.Ifname())
	}
	wantPort := WireguardListenPortBase + int(srv.Index)
	if device.ListenPort != wantPort {
		return fmt.Errorf("%s listens on port %d, expected %d", srv.Ifname(), device.ListenPort, wantPort)
	}
	return nil
}

func (srv *Server) liveBindInterface() (netlink.Link, error) {
	if srv.BindIface == nil || srv.BindIface.Attrs() == nil {
		return nil, fmt.Errorf("bind interface is not configured")
	}

	attrs := srv.BindIface.Attrs()
	var (
		link netlink.Link
		err  error
	)
	if attrs.Index > 0 {
		link, err = netlink.LinkByIndex(attrs.Index)
	} else {
		link, err = netlink.LinkByName(attrs.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find bind interface %s: %v", attrs.Name, err)
	}
	return link, nil
}

func (srv *Server) checkBindInterface() error {
	link, err := srv.liveBindInterface()
	if err != nil {
		return err
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return fmt.Errorf("bind interface %s is down", link.Attrs().Name)
	}
	return nil
}

func (srv *Server) checkBindAddress() error {
	link, err := srv.liveBindInterface()
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, netlinkFamilyV4)
	if err != nil {
		return fmt.Errorf("failed to list addresses on %s: %v", link.Attrs().Name, err)
	}
	want := addrToIp(srv.BindAddr)
	for _, addr := range addrs {
		if addr.IP.Equal(want) {
			return nil
		}
	}
	return fmt.Errorf("bind address %s is missing from %s", srv.BindAddr, link.Attrs().Name)
}

func (srv *Server) checkDefaultRoute() error {
	if srv.BindIface == nil || srv.BindIface.Attrs() == nil {
		return fmt.Errorf("bind interface is not configured")
	}
	routes, err := netlink.RouteList(nil, netlinkFamilyV4)
	if err != nil {
		return fmt.Errorf("failed to list IPv4 routes: %v", err)
	}

	foundDefault := false
	for _, route := range routes {
		if !isDefaultIPv4Route(route) {
			continue
		}
		foundDefault = true
		if route.LinkIndex == srv.BindIface.Attrs().Index {
			return nil
		}
	}
	if !foundDefault {
		return fmt.Errorf("IPv4 default route is missing")
	}
	return fmt.Errorf("IPv4 default route does not use %s", srv.BindIface.Attrs().Name)
}

func isDefaultIPv4Route(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, bits := route.Dst.Mask.Size()
	return route.Dst.IP.To4() != nil && ones == 0 && bits == 32
}

func checkIPv4Forwarding() error {
	value, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("failed to read IPv4 forwarding state: %v", err)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return fmt.Errorf("IPv4 forwarding is disabled")
	}
	return nil
}

func (srv *Server) checkIptablesRules() error {
	if srv.Ipt == nil {
		return fmt.Errorf("iptables client is unavailable")
	}
	for _, rule := range srv.requiredIptablesRules() {
		exists, err := srv.Ipt.Exists(rule.table, rule.chain, rule.spec...)
		if err != nil {
			return fmt.Errorf("failed to inspect %s: %v", rule.description, err)
		}
		if !exists {
			return fmt.Errorf("%s is missing", rule.description)
		}
	}
	return nil
}

func (srv *Server) checkPeerCapacity() error {
	if srv.ipAllocator == nil || !srv.ipAllocator.HasCapacity() {
		return fmt.Errorf("WireGuard peer address pool is exhausted")
	}
	return nil
}
