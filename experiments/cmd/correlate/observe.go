package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// view is the correlator's GET /v1/incidents item (correlator/server/view.go).
type view struct {
	At        time.Time `json:"at"`
	Namespace string    `json:"namespace"`
	Service   string    `json:"service"`
	Pod       string    `json:"pod"`
	Rule      string    `json:"rule"`
	Priority  string    `json:"priority"`
	Output    string    `json:"output"`
	Deploy    *struct {
		App      string    `json:"app"`
		Revision string    `json:"revision"`
		At       time.Time `json:"at"`
	} `json:"deployment"`
	Traces []struct {
		TraceID    string    `json:"trace_id"`
		Service    string    `json:"service"`
		Start      time.Time `json:"start"`
		DurationMs float64   `json:"duration_ms"`
		Error      bool      `json:"error"`
	} `json:"traces"`
}

func (v view) alert() (incident.SecurityAlert, error) {
	p, err := incident.ParsePriority(v.Priority)
	if err != nil {
		return incident.SecurityAlert{}, err
	}
	return incident.SecurityAlert{
		Rule: v.Rule, Priority: p, Output: v.Output, Pod: v.Pod, At: v.At,
		Workload: incident.Workload{Namespace: v.Namespace, Service: v.Service},
	}, nil
}

func (v view) reportedCause() *incident.Deployment {
	if v.Deploy == nil {
		return nil
	}
	return &incident.Deployment{App: v.Deploy.App, Revision: v.Deploy.Revision, Namespace: v.Namespace, At: v.Deploy.At}
}

func (v view) reportedTraces() []incident.TraceRef {
	out := make([]incident.TraceRef, len(v.Traces))
	for i, t := range v.Traces {
		out[i] = incident.TraceRef{
			TraceID: t.TraceID, Service: t.Service, Start: t.Start,
			Duration: time.Duration(t.DurationMs * float64(time.Millisecond)), Error: t.Error,
		}
	}
	return out
}

func (v view) traceIDs() []string {
	ids := make([]string, len(v.Traces))
	for i, t := range v.Traces {
		ids[i] = t.TraceID
	}
	return ids
}

type correlatorClient struct {
	baseURL string
	http    *http.Client
}

// find returns the incident whose Falco output carries marker.
func (c correlatorClient) find(ctx context.Context, marker string) (view, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/incidents", nil)
	if err != nil {
		return view{}, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return view{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return view{}, false, fmt.Errorf("correlator: status %d", resp.StatusCode)
	}
	var views []view
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		return view{}, false, err
	}
	for _, v := range views {
		if strings.Contains(v.Output, marker) {
			return v, true, nil
		}
	}
	return view{}, false, nil
}

// observation is what the harness saw of one incident over time.
type observation struct {
	first, final           view
	firstSeen, finalSeenAt time.Time
	delivered              bool
}

// watch polls until the incident for marker appears (or deliveryTimeout
// passes), then until settleAfter past the alert, recording when its trace
// list last changed: the post-alert refresh.
func (c correlatorClient) watch(ctx context.Context, marker string, deliveryTimeout, settleAfter time.Duration) (observation, error) {
	var obs observation
	deadline := time.Now().Add(deliveryTimeout)
	for !obs.delivered {
		v, ok, err := c.find(ctx, marker)
		if err != nil {
			return obs, err
		}
		if ok {
			obs = observation{first: v, final: v, firstSeen: time.Now(), finalSeenAt: time.Now(), delivered: true}
			break
		}
		if time.Now().After(deadline) {
			return obs, nil
		}
		if err := sleep(ctx, 500*time.Millisecond); err != nil {
			return obs, err
		}
	}
	for time.Now().Before(obs.first.At.Add(settleAfter)) {
		if err := sleep(ctx, 2*time.Second); err != nil {
			return obs, err
		}
		v, ok, err := c.find(ctx, marker)
		if err != nil {
			return obs, err
		}
		if ok && !slices.Equal(v.traceIDs(), obs.final.traceIDs()) {
			obs.final, obs.finalSeenAt = v, time.Now()
		}
	}
	return obs, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
