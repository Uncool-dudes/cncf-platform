package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

type fakeTraces struct {
	mu    sync.Mutex
	calls int
	// byCall[i] is returned on the i-th lookup.
	byCall [][]incident.TraceRef
}

func (f *fakeTraces) FindTraces(context.Context, incident.Workload, time.Time, time.Time) ([]incident.TraceRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.byCall[min(f.calls, len(f.byCall)-1)]
	f.calls++
	return out, nil
}

type fakeAnnotator struct {
	created []string
	updated map[int64]string
}

func (f *fakeAnnotator) Annotate(_ context.Context, _ time.Time, text string, _ []string) (int64, error) {
	f.created = append(f.created, text)
	return int64(len(f.created)), nil
}

func (f *fakeAnnotator) UpdateText(_ context.Context, id int64, text string) error {
	f.updated[id] = text
	return nil
}

func newTestServer(traces *fakeTraces, ann *fakeAnnotator) (*Server, http.Handler, *[]func()) {
	var scheduled []func()
	s := &Server{
		Traces:    traces,
		Annotator: ann,
		Window:    incident.Window{DeployLookback: 30 * time.Minute, TraceSpan: 2 * time.Minute, MaxTraces: 5},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Keep:      10,
		After:     func(_ time.Duration, f func()) { scheduled = append(scheduled, f) },
	}
	return s, s.Handler(), &scheduled
}

func falcoBody(at time.Time) string {
	return `{"rule":"Shell spawned in platform workload","priority":"Warning","output":"shell",
	  "time":"` + at.Format(time.RFC3339Nano) + `",
	  "output_fields":{"k8s.ns.name":"shop","k8s.pod.name":"checkout-7d9f8b6c5-x2k4p"}}`
}

func incidents(t *testing.T, h http.Handler) []incidentView {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/incidents", nil))
	var out []incidentView
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func post(t *testing.T, h http.Handler, path, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST %s = %d: %s", path, rec.Code, rec.Body)
	}
}

func TestFalcoAlertIsRefreshedWithTracesAfterTheAlert(t *testing.T) {
	at := time.Now().UTC()
	before := incident.TraceRef{TraceID: "before", Start: at.Add(-30 * time.Second)}
	after := incident.TraceRef{TraceID: "after", Start: at.Add(30 * time.Second), Error: true}
	traces := &fakeTraces{byCall: [][]incident.TraceRef{{before}, {before, after}}}
	ann := &fakeAnnotator{updated: map[int64]string{}}
	_, h, scheduled := newTestServer(traces, ann)

	post(t, h, "/v1/falco", falcoBody(at))
	got := incidents(t, h)
	if len(got) != 1 || len(got[0].Traces) != 1 || got[0].Traces[0].TraceID != "before" {
		t.Fatalf("initial incident = %+v", got)
	}
	if len(*scheduled) != 1 {
		t.Fatalf("want one scheduled refresh, got %d", len(*scheduled))
	}

	(*scheduled)[0]()

	got = incidents(t, h)
	if len(got[0].Traces) != 2 || got[0].Traces[0].TraceID != "after" {
		t.Fatalf("refreshed traces = %+v, want error trace 'after' first", got[0].Traces)
	}
	if !strings.Contains(ann.updated[got[0].ID], "trace after") {
		t.Fatalf("annotation not updated with new trace: %q", ann.updated[got[0].ID])
	}
}

func TestSeededDeploymentIsFoundAfterRestart(t *testing.T) {
	at := time.Now().UTC()
	traces := &fakeTraces{byCall: [][]incident.TraceRef{nil}}
	s, h, _ := newTestServer(traces, &fakeAnnotator{updated: map[int64]string{}})
	s.Seed([]incident.Deployment{{App: "shop", Revision: "abc123", Namespace: "shop", At: at.Add(-3 * time.Minute)}})

	post(t, h, "/v1/falco", falcoBody(at))

	got := incidents(t, h)
	if got[0].Deployment == nil || got[0].Deployment.Revision != "abc123" {
		t.Fatalf("deployment = %+v, want seeded abc123", got[0].Deployment)
	}
}

func TestArgoCDSyncIsRecordedAndUnsuccessfulSyncIgnored(t *testing.T) {
	at := time.Now().UTC()
	traces := &fakeTraces{byCall: [][]incident.TraceRef{nil}}
	ann := &fakeAnnotator{updated: map[int64]string{}}
	_, h, _ := newTestServer(traces, ann)

	post(t, h, "/v1/argocd", `{"app":"shop","revision":"bad","namespace":"shop","phase":"Failed","finishedAt":"`+at.Add(-time.Minute).Format(time.RFC3339)+`"}`)
	post(t, h, "/v1/argocd", `{"app":"shop","revision":"good","namespace":"shop","phase":"Succeeded","finishedAt":"`+at.Add(-2*time.Minute).Format(time.RFC3339)+`"}`)
	post(t, h, "/v1/falco", falcoBody(at))

	got := incidents(t, h)
	if got[0].Deployment == nil || got[0].Deployment.Revision != "good" {
		t.Fatalf("deployment = %+v, want good", got[0].Deployment)
	}
	if len(ann.created) != 2 {
		t.Fatalf("annotations = %v, want sync + alert", ann.created)
	}
}

func TestHostAlertWithoutWorkloadIsAcceptedAndDropped(t *testing.T) {
	traces := &fakeTraces{byCall: [][]incident.TraceRef{nil}}
	_, h, _ := newTestServer(traces, &fakeAnnotator{updated: map[int64]string{}})
	post(t, h, "/v1/falco", `{"rule":"x","priority":"Notice","time":"2026-11-05T12:00:00Z","output_fields":{}}`)
	if got := incidents(t, h); len(got) != 0 {
		t.Fatalf("host alert produced incidents: %+v", got)
	}
}
