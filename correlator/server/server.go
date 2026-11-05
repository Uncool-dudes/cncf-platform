// Package server is the correlator's HTTP shell: it receives Falco and Argo CD
// webhooks, fetches trace context, and hands everything to incident.Correlate.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/uncool-dudes/cncf-platform/correlator/argocd"
	"github.com/uncool-dudes/cncf-platform/correlator/falco"
	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// TraceFinder fetches trace summaries for a workload in a time range.
type TraceFinder interface {
	FindTraces(ctx context.Context, w incident.Workload, from, to time.Time) ([]incident.TraceRef, error)
}

// Annotator marks an event on shared dashboards and can amend its text.
type Annotator interface {
	Annotate(ctx context.Context, at time.Time, text string, tags []string) (int64, error)
	UpdateText(ctx context.Context, id int64, text string) error
}

// Server holds recent deployments and incidents in memory. Deployments are
// re-seeded from Argo CD at startup (see Seed); incidents are not.
type Server struct {
	Traces    TraceFinder
	Annotator Annotator
	Window    incident.Window
	// IndexLag is how long the trace backend takes to make a trace
	// searchable; the post-alert refresh waits TraceSpan + IndexLag.
	IndexLag time.Duration
	Log      *slog.Logger
	// Keep bounds each in-memory history.
	Keep int
	// After schedules the post-alert trace refresh; time.AfterFunc when nil.
	// Tests replace it to run the refresh synchronously.
	After func(d time.Duration, f func())

	mu          sync.Mutex
	nextID      int64
	deployments []incident.Deployment
	incidents   []record

	incidentsTotal *prometheus.CounterVec
	deployToAlert  *prometheus.HistogramVec
	deploysTotal   *prometheus.CounterVec
	registry       *prometheus.Registry
}

// record is a stored incident plus what is needed to refresh it.
type record struct {
	id           int64
	annotationID int64
	inc          incident.Incident
}

// Seed loads deployments that happened before this process started, so an
// alert right after a restart still finds the sync that preceded it.
func (s *Server) Seed(deps []incident.Deployment) {
	for _, d := range deps {
		s.recordDeployment(d)
	}
}

// Handler returns the routes, registering metrics on a private registry.
func (s *Server) Handler() http.Handler {
	s.registry = prometheus.NewRegistry()
	s.incidentsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "correlator_incidents_total",
		Help: "Falco alerts correlated, by workload, rule, priority and whether a GitOps sync preceded them.",
	}, []string{"workload_namespace", "workload", "rule", "priority", "after_deploy"})
	s.deployToAlert = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "correlator_deploy_to_alert_seconds",
		Help:    "Time from the last GitOps sync to a security alert in the same namespace.",
		Buckets: prometheus.ExponentialBuckets(5, 2, 10),
	}, []string{"workload_namespace", "revision"})
	s.deploysTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "correlator_deployments_total",
		Help: "Successful Argo CD syncs received.",
	}, []string{"app", "workload_namespace"})
	s.registry.MustRegister(s.incidentsTotal, s.deployToAlert, s.deploysTotal)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/falco", s.handleFalco)
	mux.HandleFunc("POST /v1/argocd", s.handleArgoCD)
	mux.HandleFunc("GET /v1/incidents", s.handleIncidents)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))
	return mux
}

func (s *Server) handleArgoCD(w http.ResponseWriter, r *http.Request) {
	dep, err := argocd.Decode(r.Body)
	if errors.Is(err, argocd.ErrNotSucceeded) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.recordDeployment(dep)
	s.deploysTotal.WithLabelValues(dep.App, dep.Namespace).Inc()
	if _, err := s.Annotator.Annotate(r.Context(), dep.At, "Argo CD sync "+dep.App+" @ "+shortRev(dep.Revision),
		[]string{"deploy", dep.App, dep.Namespace}); err != nil {
		s.Log.Warn("grafana annotation failed", "err", err)
	}
	w.WriteHeader(http.StatusAccepted)
}

// handleFalco correlates with the traces available now (the half-window
// before the alert), then schedules one refresh once the half-window after
// the alert has elapsed and its traces have been indexed.
func (s *Server) handleFalco(w http.ResponseWriter, r *http.Request) {
	alert, err := falco.Decode(r.Body)
	if errors.Is(err, incident.ErrUnknownWorkload) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	inc := s.correlate(r.Context(), alert)
	id := s.recordIncident(inc)
	s.observe(inc)
	annotationID, err := s.Annotator.Annotate(r.Context(), alert.At, incidentText(inc),
		[]string{"falco", alert.Priority.String(), alert.Workload.Service})
	if err != nil {
		s.Log.Warn("grafana annotation failed", "err", err)
	}
	s.setAnnotationID(id, annotationID)
	s.after(time.Until(alert.At.Add(s.Window.TraceSpan+s.IndexLag)), func() { s.refresh(id) })
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) correlate(ctx context.Context, alert incident.SecurityAlert) incident.Incident {
	from, to := s.Window.TraceRange(alert.At)
	traces, err := s.Traces.FindTraces(ctx, alert.Workload, from, to)
	if err != nil {
		s.Log.Warn("trace lookup failed; correlating without traces", "service", alert.Workload.Service, "err", err)
	}
	return incident.Correlate(alert, s.recentDeployments(), traces, s.Window)
}

// refresh re-correlates a stored incident over the full trace window and
// rewrites its annotation. Metrics are not re-observed: they count alerts.
func (s *Server) refresh(id int64) {
	rec, ok := s.lookup(id)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	inc := s.correlate(ctx, rec.inc.Alert)
	s.replaceIncident(id, inc)
	if rec.annotationID == 0 {
		return
	}
	if err := s.Annotator.UpdateText(ctx, rec.annotationID, incidentText(inc)); err != nil {
		s.Log.Warn("grafana annotation update failed", "err", err)
	}
}

func (s *Server) handleIncidents(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]incidentView, 0, len(s.incidents))
	for i := len(s.incidents) - 1; i >= 0; i-- {
		out = append(out, viewOf(s.incidents[i].id, s.incidents[i].inc))
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) after(d time.Duration, f func()) {
	if s.After != nil {
		s.After(d, f)
		return
	}
	time.AfterFunc(max(d, 0), f)
}

func (s *Server) recordDeployment(d incident.Deployment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deployments = keepLast(append(s.deployments, d), s.Keep)
}

func (s *Server) recentDeployments() []incident.Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]incident.Deployment(nil), s.deployments...)
}

func (s *Server) recordIncident(inc incident.Incident) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.incidents = keepLast(append(s.incidents, record{id: s.nextID, inc: inc}), s.Keep)
	return s.nextID
}

func (s *Server) lookup(id int64) (record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.incidents {
		if r.id == id {
			return r, true
		}
	}
	return record{}, false
}

func (s *Server) setAnnotationID(id, annotationID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.incidents {
		if s.incidents[i].id == id {
			s.incidents[i].annotationID = annotationID
		}
	}
}

func (s *Server) replaceIncident(id int64, inc incident.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.incidents {
		if s.incidents[i].id == id {
			s.incidents[i].inc = inc
		}
	}
}

func (s *Server) observe(inc incident.Incident) {
	a := inc.Alert
	afterDeploy := "false"
	if inc.LastDeployment != nil {
		afterDeploy = "true"
		s.deployToAlert.WithLabelValues(a.Workload.Namespace, shortRev(inc.LastDeployment.Revision)).
			Observe(inc.SinceDeploy.Seconds())
	}
	s.incidentsTotal.WithLabelValues(a.Workload.Namespace, a.Workload.Service, a.Rule, a.Priority.String(), afterDeploy).Inc()
}

func keepLast[T any](xs []T, n int) []T {
	if len(xs) <= n {
		return xs
	}
	return append([]T(nil), xs[len(xs)-n:]...)
}

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func incidentText(inc incident.Incident) string {
	var b strings.Builder
	b.WriteString(inc.Alert.Rule + " in " + inc.Alert.Pod)
	if inc.LastDeployment != nil {
		b.WriteString(" | " + inc.SinceDeploy.Round(time.Second).String() + " after sync @ " + shortRev(inc.LastDeployment.Revision))
	}
	for _, t := range inc.Traces {
		b.WriteString(" | trace " + t.TraceID)
	}
	return b.String()
}
