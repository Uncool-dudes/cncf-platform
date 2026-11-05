package server

import (
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// incidentView is the JSON shape of GET /v1/incidents.
type incidentView struct {
	ID           int64       `json:"id"`
	At           time.Time   `json:"at"`
	Namespace    string      `json:"namespace"`
	Service      string      `json:"service"`
	Pod          string      `json:"pod"`
	Rule         string      `json:"rule"`
	Priority     string      `json:"priority"`
	Output       string      `json:"output"`
	Deployment   *deployView `json:"deployment,omitempty"`
	SinceDeployS float64     `json:"since_deploy_seconds,omitempty"`
	Traces       []traceView `json:"traces"`
}

type deployView struct {
	App      string    `json:"app"`
	Revision string    `json:"revision"`
	At       time.Time `json:"at"`
}

type traceView struct {
	TraceID    string    `json:"trace_id"`
	Service    string    `json:"service"`
	Start      time.Time `json:"start"`
	DurationMs float64   `json:"duration_ms"`
	Error      bool      `json:"error"`
}

func viewOf(id int64, inc incident.Incident) incidentView {
	a := inc.Alert
	v := incidentView{
		ID: id, At: a.At, Namespace: a.Workload.Namespace, Service: a.Workload.Service, Pod: a.Pod,
		Rule: a.Rule, Priority: a.Priority.String(), Output: a.Output, Traces: []traceView{},
	}
	if d := inc.LastDeployment; d != nil {
		v.Deployment = &deployView{App: d.App, Revision: d.Revision, At: d.At}
		v.SinceDeployS = inc.SinceDeploy.Seconds()
	}
	for _, t := range inc.Traces {
		v.Traces = append(v.Traces, traceView{
			TraceID: t.TraceID, Service: t.Service, Start: t.Start,
			DurationMs: float64(t.Duration.Microseconds()) / 1000, Error: t.Error,
		})
	}
	return v
}
