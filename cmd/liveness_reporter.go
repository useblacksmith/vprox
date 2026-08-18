package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/modal-labs/vprox/lib"
)

type LivenessReporter struct {
	client            http.Client
	backendEndpoint   string
	backendAdminToken string
	ip                string
	region            string
	readinessProvider func() lib.ReadinessSnapshot
	healthLogMu       sync.Mutex
	loggedStatus      lib.ReadinessStatus
	loggedReason      lib.ReadinessReason
}

func (r *LivenessReporter) Report(ctx context.Context) {
	readiness := lib.ReadinessSnapshot{
		Status: lib.ReadinessStarting,
		Reason: lib.ReadinessReasonStarting,
	}
	if r.readinessProvider != nil {
		readiness = r.readinessProvider()
	}
	healthy := readiness.RoutingEligible()
	r.logFailure(readiness)

	requestBody := struct {
		IP      string `json:"ip"`
		Region  string `json:"region"`
		Healthy bool   `json:"healthy"`
	}{
		IP:      r.ip,
		Region:  r.region,
		Healthy: healthy,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		fmt.Printf("failed to marshal request body: %v\n", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/admin/staticip/liveness", r.backendEndpoint), bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("failed to create request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.backendAdminToken))

	resp, err := r.client.Do(req)
	if err != nil {
		fmt.Printf("failed to send request: %v\n", err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("failed to close response body: %v\n", err)
		}
	}()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		fmt.Printf("error reporting liveness: unexpected status code: %d\n", resp.StatusCode)
	}
}

func (r *LivenessReporter) logFailure(readiness lib.ReadinessSnapshot) {
	r.healthLogMu.Lock()
	defer r.healthLogMu.Unlock()

	if readiness.Status != lib.ReadinessUnhealthy && readiness.Status != lib.ReadinessStale {
		r.loggedStatus = ""
		r.loggedReason = ""
		return
	}
	if readiness.Status == r.loggedStatus && readiness.Reason == r.loggedReason {
		return
	}

	log.Printf("[%s] static IP readiness is %s (%s)", r.ip, readiness.Status, readiness.Reason)
	r.loggedStatus = readiness.Status
	r.loggedReason = readiness.Reason
}

const (
	minLivenessReportInterval = 1500 * time.Millisecond
	maxLivenessReportInterval = 2 * time.Second
)

func (r *LivenessReporter) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(r.randomInterval())
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.Report(ctx)
				ticker.Reset(r.randomInterval())
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (r *LivenessReporter) randomInterval() time.Duration {
	return time.Duration(rand.Int63n(int64(maxLivenessReportInterval-minLivenessReportInterval))) + minLivenessReportInterval
}
