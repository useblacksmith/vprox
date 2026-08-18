package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modal-labs/vprox/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capturedLivenessRequest struct {
	path          string
	method        string
	authorization string
	body          map[string]any
}

func TestLivenessReporterIncludesReadiness(t *testing.T) {
	received := make(chan capturedLivenessRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- capturedLivenessRequest{
			path:          r.URL.Path,
			method:        r.Method,
			authorization: r.Header.Get("Authorization"),
			body:          body,
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	reporter := &LivenessReporter{
		client:            http.Client{Timeout: time.Second},
		backendEndpoint:   server.URL,
		backendAdminToken: "admin-token",
		ip:                "192.0.2.10",
		region:            "test-region",
		readinessProvider: func() lib.ReadinessSnapshot {
			return lib.ReadinessSnapshot{
				Status:              lib.ReadinessUnhealthy,
				Reason:              lib.ReadinessReasonDefaultRouteInvalid,
				ConsecutiveFailures: 3,
			}
		},
	}

	reporter.Report(context.Background())
	request := <-received
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, "/api/admin/staticip/liveness", request.path)
	assert.Equal(t, "Bearer admin-token", request.authorization)
	assert.Equal(t, "192.0.2.10", request.body["ip"])
	assert.Equal(t, "test-region", request.body["region"])

	readiness, ok := request.body["readiness"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "unhealthy", readiness["status"])
	assert.Equal(t, "default_route_invalid", readiness["reason"])
	assert.Equal(t, float64(3), readiness["consecutive_failures"])
}

func TestLivenessReporterOmitsReadinessWithoutProvider(t *testing.T) {
	received := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reporter := &LivenessReporter{
		client:          http.Client{Timeout: time.Second},
		backendEndpoint: server.URL,
		ip:              "192.0.2.10",
		region:          "test-region",
	}
	reporter.Report(context.Background())

	body := <-received
	assert.NotContains(t, body, "readiness")
}
