package lib

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestReadinessTrackerHysteresis(t *testing.T) {
	start := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	tracker := newReadinessTracker(start, readinessStaleAfter)

	initial := tracker.get(start)
	assert.Equal(t, ReadinessStarting, initial.Status)
	assert.False(t, initial.RoutingEligible())

	healthy := tracker.recordSuccess(start.Add(time.Second), 20*time.Millisecond)
	assert.Equal(t, ReadinessHealthy, healthy.Status)
	assert.True(t, healthy.RoutingEligible())

	for failure := 1; failure <= readinessFailureLimit; failure++ {
		snapshot := tracker.recordFailure(
			start.Add(time.Duration(failure+1)*time.Second),
			10*time.Millisecond,
			ReadinessReasonDefaultRouteInvalid,
		)
		assert.Equal(t, failure, snapshot.ConsecutiveFailures)
		if failure < readinessFailureLimit {
			assert.Equal(t, ReadinessDegraded, snapshot.Status)
			assert.True(t, snapshot.RoutingEligible())
		} else {
			assert.Equal(t, ReadinessUnhealthy, snapshot.Status)
			assert.False(t, snapshot.RoutingEligible())
		}
	}

	recovering := tracker.recordSuccess(start.Add(10*time.Second), 5*time.Millisecond)
	assert.Equal(t, ReadinessUnhealthy, recovering.Status)
	assert.Equal(t, ReadinessReasonRecovering, recovering.Reason)
	assert.False(t, recovering.RoutingEligible())

	failedRecovery := tracker.recordFailure(
		start.Add(11*time.Second),
		5*time.Millisecond,
		ReadinessReasonDefaultRouteInvalid,
	)
	assert.Equal(t, ReadinessUnhealthy, failedRecovery.Status)

	stillRecovering := tracker.recordSuccess(start.Add(12*time.Second), 5*time.Millisecond)
	assert.Equal(t, ReadinessUnhealthy, stillRecovering.Status)
	recovered := tracker.recordSuccess(start.Add(13*time.Second), 5*time.Millisecond)
	assert.Equal(t, ReadinessHealthy, recovered.Status)
	assert.Empty(t, recovered.Reason)
	assert.True(t, recovered.RoutingEligible())
}

func TestReadinessDoesNotAdvertiseBeforeFirstSuccess(t *testing.T) {
	start := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	tracker := newReadinessTracker(start, readinessStaleAfter)

	for failure := 1; failure < readinessFailureLimit; failure++ {
		snapshot := tracker.recordFailure(
			start.Add(time.Duration(failure)*time.Second),
			time.Millisecond,
			ReadinessReasonWireGuardUnavailable,
		)
		assert.Equal(t, ReadinessStarting, snapshot.Status)
	}
}

func TestReadinessBecomesStale(t *testing.T) {
	start := time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)
	tracker := newReadinessTracker(start, readinessStaleAfter)

	assert.Equal(t, ReadinessStale, tracker.get(start.Add(readinessStaleAfter+time.Second)).Status)

	checkedAt := start.Add(2 * time.Minute)
	tracker.recordSuccess(checkedAt, time.Millisecond)
	snapshot := tracker.get(checkedAt.Add(readinessStaleAfter + time.Second))
	assert.Equal(t, ReadinessStale, snapshot.Status)
	assert.Equal(t, ReadinessReasonCheckStale, snapshot.Reason)
	assert.False(t, snapshot.RoutingEligible())

	firstSuccess := tracker.recordSuccess(checkedAt.Add(readinessStaleAfter+2*time.Second), time.Millisecond)
	assert.Equal(t, ReadinessUnhealthy, firstSuccess.Status)
	assert.Equal(t, ReadinessReasonRecovering, firstSuccess.Reason)
	assert.Equal(t, ReadinessHealthy,
		tracker.recordSuccess(checkedAt.Add(readinessStaleAfter+3*time.Second), time.Millisecond).Status)
}

func TestRunReadinessChecksStopsAtFirstFailure(t *testing.T) {
	var calls []string
	checks := []readinessCheck{
		{reason: ReadinessReasonListenerUnavailable, check: func() error {
			calls = append(calls, "listener")
			return nil
		}},
		{reason: ReadinessReasonDefaultRouteInvalid, check: func() error {
			calls = append(calls, "route")
			return errors.New("route missing")
		}},
		{reason: ReadinessReasonIptablesRuleMissing, check: func() error {
			calls = append(calls, "iptables")
			return nil
		}},
	}

	reason, err := runReadinessChecks(checks)
	require.EqualError(t, err, "route missing")
	assert.Equal(t, ReadinessReasonDefaultRouteInvalid, reason)
	assert.Equal(t, []string{"listener", "route"}, calls)
}

func TestRequiredIptablesRules(t *testing.T) {
	srv := &Server{
		BindAddr:            netip.MustParseAddr("192.0.2.10"),
		BindIface:           &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}},
		InternalBindIface:   &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1"}},
		InternalNetworkCidr: "10.0.0.0/8",
		WgCidr:              netip.MustParsePrefix("10.1.0.1/24"),
	}

	assert.Len(t, srv.requiredIptablesRules(), 4)

	srv.Region = "us-west"
	rules := srv.requiredIptablesRules()
	require.Len(t, rules, 7)
	assert.Equal(t, "internal SNAT rule", rules[4].description)
	assert.Contains(t, rules[4].spec, internalSnatRuleComment)
}

func TestIsDefaultIPv4Route(t *testing.T) {
	assert.True(t, isDefaultIPv4Route(netlink.Route{}))
	assert.True(t, isDefaultIPv4Route(netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
	}))
	assert.False(t, isDefaultIPv4Route(netlink.Route{
		Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(1, 32)},
	}))
	assert.False(t, isDefaultIPv4Route(netlink.Route{
		Dst: &net.IPNet{IP: net.ParseIP("::"), Mask: net.CIDRMask(0, 128)},
	}))
}
