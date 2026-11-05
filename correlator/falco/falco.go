// Package falco decodes Falcosidekick webhook payloads into security alerts.
package falco

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// payload is Falcosidekick's webhook body (one Falco event).
type payload struct {
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Time         time.Time      `json:"time"`
	OutputFields map[string]any `json:"output_fields"`
}

// Decode reads one Falcosidekick webhook body. Alerts from pods outside any
// namespace (host processes) return incident.ErrUnknownWorkload.
func Decode(r io.Reader) (incident.SecurityAlert, error) {
	var p payload
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return incident.SecurityAlert{}, fmt.Errorf("decode falco payload: %w", err)
	}
	prio, err := incident.ParsePriority(p.Priority)
	if err != nil {
		return incident.SecurityAlert{}, err
	}
	ns, _ := p.OutputFields["k8s.ns.name"].(string)
	pod, _ := p.OutputFields["k8s.pod.name"].(string)
	wl, err := incident.WorkloadFromPod(ns, pod)
	if err != nil {
		return incident.SecurityAlert{}, err
	}
	return incident.SecurityAlert{
		Rule: p.Rule, Priority: prio, Output: p.Output, Pod: pod, Workload: wl, At: p.Time,
	}, nil
}
