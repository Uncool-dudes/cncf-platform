// Package incident joins the three signals the reviewed literature evaluates
// in isolation - a runtime security alert (Falco), the GitOps deployment that
// preceded it (Argo CD), and the request traces around it (Tempo) - into
// one Incident for a single workload.
//
// Everything here is pure: callers fetch deployments and traces, this package
// decides how they relate.
package incident

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// Workload identifies a Kubernetes workload by namespace and service name
// (the Deployment name, which by convention is also the Service name).
type Workload struct {
	Namespace string
	Service   string
}

// ErrUnknownWorkload means an alert carried no namespace or pod to attribute.
var ErrUnknownWorkload = errors.New("alert has no namespace/pod")

// WorkloadFromPod derives the owning Deployment from a ReplicaSet-managed pod
// name ("<deployment>-<rs-hash>-<pod-hash>"), the only identity Falco reports
// without an extra API lookup.
func WorkloadFromPod(namespace, pod string) (Workload, error) {
	if namespace == "" || pod == "" {
		return Workload{}, ErrUnknownWorkload
	}
	parts := strings.Split(pod, "-")
	if len(parts) < 3 {
		return Workload{Namespace: namespace, Service: pod}, nil
	}
	return Workload{Namespace: namespace, Service: strings.Join(parts[:len(parts)-2], "-")}, nil
}

// Priority is Falco's alert priority, ordered from least to most severe.
type Priority int

const (
	PriorityDebug Priority = iota
	PriorityInformational
	PriorityNotice
	PriorityWarning
	PriorityError
	PriorityCritical
	PriorityAlert
	PriorityEmergency
)

var priorityNames = []string{"debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency"}

// ParsePriority accepts Falco's priority strings case-insensitively.
func ParsePriority(s string) (Priority, error) {
	i := slices.Index(priorityNames, strings.ToLower(s))
	if i < 0 {
		return 0, errors.New("unknown falco priority " + s)
	}
	return Priority(i), nil
}

func (p Priority) String() string { return priorityNames[p] }

// SecurityAlert is one runtime detection attributed to a workload.
type SecurityAlert struct {
	Rule     string
	Priority Priority
	Output   string
	Pod      string
	Workload Workload
	At       time.Time
}

// Deployment is one completed GitOps sync of a workload's application.
type Deployment struct {
	App      string
	Revision string
	// Namespace the Argo CD application deploys into; every workload in it
	// is considered changed by the sync.
	Namespace string
	At        time.Time
}

// TraceRef points at one trace touching the workload, with enough summary to
// rank it without fetching the full trace.
type TraceRef struct {
	TraceID  string
	Service  string
	Start    time.Time
	Duration time.Duration
	Error    bool
}

// Incident is a security alert with its deployment and trace context.
type Incident struct {
	Alert SecurityAlert
	// LastDeployment is the most recent sync into the alert's namespace
	// within the lookback window, nil if none.
	LastDeployment *Deployment
	// SinceDeploy is Alert.At - LastDeployment.At; zero when LastDeployment is nil.
	SinceDeploy time.Duration
	// Traces are the workload's traces in the window around the alert,
	// errors first, then closest in time.
	Traces []TraceRef
}

// Window bounds how far from an alert related signals are searched.
type Window struct {
	// DeployLookback is how long before an alert a sync still counts as its
	// likely cause.
	DeployLookback time.Duration
	// TraceSpan is the half-width of the trace window centred on the alert.
	TraceSpan time.Duration
	// MaxTraces caps Incident.Traces.
	MaxTraces int
}

// TraceRange returns the [start, end] interval to fetch traces for.
func (w Window) TraceRange(at time.Time) (time.Time, time.Time) {
	return at.Add(-w.TraceSpan), at.Add(w.TraceSpan)
}

// Correlate builds the Incident for alert from candidate deployments and
// traces. Inputs need not be pre-filtered or sorted.
func Correlate(alert SecurityAlert, deployments []Deployment, traces []TraceRef, w Window) Incident {
	inc := Incident{Alert: alert}

	for i := range deployments {
		d := deployments[i]
		age := alert.At.Sub(d.At)
		if d.Namespace != alert.Workload.Namespace || age < 0 || age > w.DeployLookback {
			continue
		}
		if inc.LastDeployment == nil || d.At.After(inc.LastDeployment.At) {
			inc.LastDeployment = &d
			inc.SinceDeploy = age
		}
	}

	from, to := w.TraceRange(alert.At)
	for _, t := range traces {
		if t.Start.Before(from) || t.Start.After(to) {
			continue
		}
		inc.Traces = append(inc.Traces, t)
	}
	slices.SortStableFunc(inc.Traces, func(a, b TraceRef) int {
		if a.Error != b.Error {
			if a.Error {
				return -1
			}
			return 1
		}
		return compareDuration(absDuration(a.Start.Sub(alert.At)), absDuration(b.Start.Sub(alert.At)))
	})
	if len(inc.Traces) > w.MaxTraces {
		inc.Traces = inc.Traces[:w.MaxTraces]
	}
	return inc
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func compareDuration(a, b time.Duration) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
