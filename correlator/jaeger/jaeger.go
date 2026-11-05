// Package jaeger finds traces for a workload through Jaeger's query HTTP API.
package jaeger

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// Client queries one Jaeger instance.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Limit   int
}

type tag struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

type span struct {
	StartTime int64 `json:"startTime"` // microseconds
	Duration  int64 `json:"duration"`  // microseconds
	Tags      []tag `json:"tags"`
}

type trace struct {
	TraceID string `json:"traceID"`
	Spans   []span `json:"spans"`
}

// ServiceNames lists the names a workload's spans may carry: Istio's sidecar
// reports "<service>.<namespace>", an OTel SDK typically reports the bare
// configured service name.
func ServiceNames(w incident.Workload) []string {
	return []string{w.Service + "." + w.Namespace, w.Service}
}

// FindTraces returns summaries of traces for the workload that start within
// [from, to], deduplicated across its service names.
func (c Client) FindTraces(ctx context.Context, w incident.Workload, from, to time.Time) ([]incident.TraceRef, error) {
	seen := map[string]bool{}
	var refs []incident.TraceRef
	for _, svc := range ServiceNames(w) {
		traces, err := c.query(ctx, svc, from, to)
		if err != nil {
			return nil, err
		}
		for _, t := range traces {
			if seen[t.TraceID] || len(t.Spans) == 0 {
				continue
			}
			seen[t.TraceID] = true
			refs = append(refs, summarize(svc, t))
		}
	}
	return refs, nil
}

func (c Client) query(ctx context.Context, service string, from, to time.Time) ([]trace, error) {
	q := url.Values{
		"service": {service},
		"start":   {strconv.FormatInt(from.UnixMicro(), 10)},
		"end":     {strconv.FormatInt(to.UnixMicro(), 10)},
		"limit":   {strconv.Itoa(c.Limit)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/traces?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jaeger query %s: %w", service, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jaeger query %s: status %d", service, resp.StatusCode)
	}
	var body struct {
		Data []trace `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode jaeger response: %w", err)
	}
	return body.Data, nil
}

func summarize(service string, t trace) incident.TraceRef {
	start, end := t.Spans[0].StartTime, t.Spans[0].StartTime+t.Spans[0].Duration
	failed := false
	for _, s := range t.Spans {
		start = min(start, s.StartTime)
		end = max(end, s.StartTime+s.Duration)
		failed = failed || spanFailed(s)
	}
	return incident.TraceRef{
		TraceID:  t.TraceID,
		Service:  service,
		Start:    time.UnixMicro(start),
		Duration: time.Duration(end-start) * time.Microsecond,
		Error:    failed,
	}
}

// spanFailed covers both conventions present in the mesh: OTel status on
// SDK spans, and the error tag / HTTP status Envoy sets on sidecar spans.
func spanFailed(s span) bool {
	for _, t := range s.Tags {
		switch t.Key {
		case "error":
			if b, ok := t.Value.(bool); ok && b {
				return true
			}
		case "otel.status_code":
			if t.Value == "ERROR" {
				return true
			}
		case "http.status_code", "http.response.status_code":
			if code, ok := t.Value.(float64); ok && code >= 500 {
				return true
			}
		}
	}
	return false
}
