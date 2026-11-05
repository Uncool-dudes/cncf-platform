// Package tempo finds traces for a workload through Grafana Tempo's search
// API (TraceQL), https://grafana.com/docs/tempo/latest/api_docs/#search.
package tempo

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

// Client queries one Tempo instance.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	Limit   int
}

// workloadMatch selects a workload's spans under both naming schemes in
// the mesh: Istio's sidecar reports "<service>.<namespace>"; an OTel SDK
// reports the bare configured name, which other namespaces may share, so
// it is scoped by the k8s.namespace.name the collector's k8sattributes
// processor adds.
func workloadMatch(w incident.Workload) string {
	return "resource.service.name = " + strconv.Quote(w.Service+"."+w.Namespace) +
		" || (resource.service.name = " + strconv.Quote(w.Service) +
		" && resource.k8s.namespace.name = " + strconv.Quote(w.Namespace) + ")"
}

// failed matches the error conventions present in the mesh: OTel span
// status on SDK spans, numeric HTTP status on newer semconv, and Envoy's
// string http.status_code / error tags.
const failed = `status = error || span.http.response.status_code >= 500 || span.http.status_code >= 500 || span.http.status_code =~ "5.." || span.error = "true"`

// TraceQL builds the search for a workload's traces, optionally only failed ones.
func TraceQL(w incident.Workload, onlyFailed bool) string {
	if onlyFailed {
		return "{ (" + workloadMatch(w) + ") && (" + failed + ") }"
	}
	return "{ " + workloadMatch(w) + " }"
}

type searchResult struct {
	TraceID           string `json:"traceID"`
	RootServiceName   string `json:"rootServiceName"`
	StartTimeUnixNano string `json:"startTimeUnixNano"`
	// DurationMs is omitted by Tempo when it rounds to zero.
	DurationMs   int64 `json:"durationMs"`
	ServiceStats map[string]struct {
		ErrorCount int `json:"errorCount"`
	} `json:"serviceStats"`
}

// FindTraces returns summaries of the workload's traces starting within
// [from, to]. A second, failures-only search marks errors, so a failed trace
// is reported even when the first search hit its limit before reaching it.
func (c Client) FindTraces(ctx context.Context, w incident.Workload, from, to time.Time) ([]incident.TraceRef, error) {
	all, err := c.search(ctx, TraceQL(w, false), from, to)
	if err != nil {
		return nil, err
	}
	failures, err := c.search(ctx, TraceQL(w, true), from, to)
	if err != nil {
		return nil, err
	}

	failedIDs := map[string]bool{}
	for _, t := range failures {
		failedIDs[t.TraceID] = true
	}
	seen := map[string]bool{}
	var refs []incident.TraceRef
	for _, t := range append(all, failures...) {
		if seen[t.TraceID] {
			continue
		}
		seen[t.TraceID] = true
		ref, err := summarize(t, failedIDs[t.TraceID])
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func (c Client) search(ctx context.Context, traceQL string, from, to time.Time) ([]searchResult, error) {
	q := url.Values{
		"q":     {traceQL},
		"start": {strconv.FormatInt(from.Unix(), 10)},
		// Seconds resolution: round up so a trace in the last second is kept.
		"end":   {strconv.FormatInt(to.Add(time.Second-1).Unix(), 10)},
		"limit": {strconv.Itoa(c.Limit)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/search?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tempo search: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tempo search: status %d", resp.StatusCode)
	}
	var body struct {
		Traces []searchResult `json:"traces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode tempo response: %w", err)
	}
	return body.Traces, nil
}

func summarize(t searchResult, matchedFailure bool) (incident.TraceRef, error) {
	ns, err := strconv.ParseInt(t.StartTimeUnixNano, 10, 64)
	if err != nil {
		return incident.TraceRef{}, fmt.Errorf("trace %s start %q: %w", t.TraceID, t.StartTimeUnixNano, err)
	}
	failed := matchedFailure
	for _, s := range t.ServiceStats {
		failed = failed || s.ErrorCount > 0
	}
	return incident.TraceRef{
		TraceID:  t.TraceID,
		Service:  t.RootServiceName,
		Start:    time.Unix(0, ns),
		Duration: time.Duration(t.DurationMs) * time.Millisecond,
		Error:    failed,
	}, nil
}
