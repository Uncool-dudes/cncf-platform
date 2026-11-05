package trial

import (
	"testing"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func sync(rev string, at time.Time) *incident.Deployment {
	return &incident.Deployment{App: "eval-0", Revision: rev, Namespace: "eval-0", At: at}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name            string
		cause, reported *incident.Deployment
		want            Outcome
	}{
		{"hit", sync("a", t0), sync("a", t0), Hit},
		{"hit within notification skew", sync("a", t0), sync("a", t0.Add(time.Second)), Hit},
		{"earlier sync of same revision", sync("a", t0), sync("a", t0.Add(-time.Minute)), WrongDeploy},
		{"other revision", sync("b", t0), sync("a", t0), WrongDeploy},
		{"miss", sync("a", t0), nil, Miss},
		{"correct none", nil, nil, CorrectNone},
		{"spurious", nil, sync("a", t0), Spurious},
	}
	for _, c := range cases {
		if got := Classify(c.cause, c.reported); got != c.want {
			t.Errorf("%s: Classify = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestScoreTracesCountsOnlyPlantedTracesInsideWindow(t *testing.T) {
	w := incident.Window{TraceSpan: 2 * time.Minute, MaxTraces: 5}
	planted := []PlantedTrace{
		{TraceID: "in-ok", At: t0.Add(-time.Minute)},
		{TraceID: "in-err", At: t0.Add(time.Minute), Error: true},
		{TraceID: "outside", At: t0.Add(-10 * time.Minute)},
	}
	reported := []incident.TraceRef{{TraceID: "in-err"}, {TraceID: "unplanted"}}

	got := ScoreTraces(planted, reported, t0, w)
	if got.Recall != 0.5 || !got.ErrorCaptured {
		t.Fatalf("ScoreTraces = %+v, want recall 0.5 with error captured", got)
	}
}

func TestScoreTracesCapsRecallDenominatorAtMaxTraces(t *testing.T) {
	w := incident.Window{TraceSpan: time.Minute, MaxTraces: 2}
	planted := []PlantedTrace{{TraceID: "a", At: t0}, {TraceID: "b", At: t0}, {TraceID: "c", At: t0}}
	reported := []incident.TraceRef{{TraceID: "a"}, {TraceID: "b"}}

	if got := ScoreTraces(planted, reported, t0, w); got.Recall != 1 {
		t.Fatalf("Recall = %v, want 1: the correlator may report only MaxTraces", got.Recall)
	}
}

func TestReplayAppliesTheGivenWindow(t *testing.T) {
	alert := incident.SecurityAlert{Workload: incident.Workload{Namespace: "eval-0", Service: "frontend"}, At: t0}
	r := Record{Alert: &alert, Deployments: []incident.Deployment{*sync("a", t0.Add(-10*time.Minute))}}

	short, _ := Replay(r, incident.Window{DeployLookback: 5 * time.Minute})
	long, _ := Replay(r, incident.Window{DeployLookback: 30 * time.Minute})
	if short.LastDeployment != nil || long.LastDeployment == nil {
		t.Fatalf("lookback not applied: short=%v long=%v", short.LastDeployment, long.LastDeployment)
	}
	if _, ok := Replay(Record{}, incident.Window{}); ok {
		t.Fatal("Replay of an undelivered alert should report !ok")
	}
}
