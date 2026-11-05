// Package trial holds what one correlator evaluation trial planted and
// observed, and scores it against ground truth.
//
// A live run records every input the correlator saw (the alert, the Argo CD
// sync history, a wide window of traces), so the pure incident.Correlate can
// be replayed over other window settings without re-running the cluster.
// See experiments/README.md for the protocol.
package trial

import (
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// Scenario names how a trial relates its alert to deploys.
type Scenario string

const (
	// DeployThenAttack: a sync into the namespace, then a shell in its workload.
	// The sync is the expected cause.
	DeployThenAttack Scenario = "deploy-then-attack"
	// BackToBack: two syncs, then a shell; the second sync is the expected cause.
	BackToBack Scenario = "back-to-back"
	// AttackNoDeploy: a shell with no sync inside the lookback.
	AttackNoDeploy Scenario = "attack-no-deploy"
	// CrossNamespace: a sync into another namespace, then a shell here.
	CrossNamespace Scenario = "cross-namespace"
	// SiblingWorkload: a sync that changes only another workload in the same
	// namespace, then a shell here. The correlator matches deploys by
	// namespace, so this measures a known false-correlation mode.
	SiblingWorkload Scenario = "sibling-workload"
)

// PlantedTrace is a request the harness sent with a known trace ID.
type PlantedTrace struct {
	TraceID string    `json:"trace_id"`
	At      time.Time `json:"at"`
	Error   bool      `json:"error"`
}

// Record is one trial: ground truth, the correlator's inputs, and what it
// reported. Times are from the harness clock except where noted.
type Record struct {
	ID        string   `json:"id"`
	Scenario  Scenario `json:"scenario"`
	Namespace string   `json:"namespace"`
	Workload  string   `json:"workload"`
	// Marker is a unique token in the attack's command line; it reaches the
	// correlator through Falco's output and joins the incident to the trial.
	Marker string `json:"marker"`
	// Cause is the sync that caused the alert, nil when none did.
	Cause    *incident.Deployment `json:"cause"`
	AttackAt time.Time            `json:"attack_at"`
	Planted  []PlantedTrace       `json:"planted"`

	// Correlator inputs, as recorded after the trial.
	Alert       *incident.SecurityAlert `json:"alert"`
	Deployments []incident.Deployment   `json:"deployments"`
	Traces      []incident.TraceRef     `json:"traces"`

	// Correlator outputs. FirstSeenAt and FinalSeenAt are when the harness
	// first saw the incident and its post-refresh form.
	ReportedCause  *incident.Deployment `json:"reported_cause"`
	ReportedTraces []incident.TraceRef  `json:"reported_traces"`
	FirstSeenAt    time.Time            `json:"first_seen_at"`
	FinalSeenAt    time.Time            `json:"final_seen_at"`
}
