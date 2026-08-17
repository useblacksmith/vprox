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
)

type capturedLivenessRequest struct {
	path          string
	method        string
	authorization string
	body          map[string]any
}

func TestLivenessReporterReportsHealth(t *testing.T) {
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
		backendToken:      "admin-token",
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
	assert.Equal(t, false, request.body["healthy"])
	assert.NotContains(t, request.body, "readiness")
}
