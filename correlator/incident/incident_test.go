package incident

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func window() Window {
	return Window{DeployLookback: 30 * time.Minute, TraceSpan: 2 * time.Minute, MaxTraces: 3}
}

func alertAt(at time.Time) SecurityAlert {
	return SecurityAlert{Rule: "shell", Priority: PriorityWarning, Workload: Workload{"shop", "checkout"}, At: at}
}

func TestWorkloadFromPodStripsReplicaSetAndPodHashes(t *testing.T) {
	cases := map[string]string{
		"checkout-7d9f8b6c5-x2k4p":      "checkout",
		"order-history-5c6d7f8b9-abcde": "order-history",
		"standalone":                    "standalone",
	}
	for pod, want := range cases {
		got, err := WorkloadFromPod("shop", pod)
		if err != nil || got.Service != want {
			t.Errorf("WorkloadFromPod(%q) = %v, %v; want %q", pod, got, err, want)
		}
	}
}

func TestWorkloadFromPodRejectsMissingIdentity(t *testing.T) {
	if _, err := WorkloadFromPod("", "checkout-1-2"); !errors.Is(err, ErrUnknownWorkload) {
		t.Fatalf("want ErrUnknownWorkload, got %v", err)
	}
}

func TestCorrelatePicksLatestSyncInNamespaceWithinLookback(t *testing.T) {
	deps := []Deployment{
		{App: "shop", Revision: "old", Namespace: "shop", At: t0.Add(-20 * time.Minute)},
		{App: "shop", Revision: "new", Namespace: "shop", At: t0.Add(-5 * time.Minute)},
		{App: "falco", Revision: "other-ns", Namespace: "falco", At: t0.Add(-1 * time.Minute)},
		{App: "shop", Revision: "after-alert", Namespace: "shop", At: t0.Add(1 * time.Minute)},
		{App: "shop", Revision: "too-old", Namespace: "shop", At: t0.Add(-2 * time.Hour)},
	}
	inc := Correlate(alertAt(t0), deps, nil, window())
	if inc.LastDeployment == nil || inc.LastDeployment.Revision != "new" {
		t.Fatalf("LastDeployment = %+v, want revision new", inc.LastDeployment)
	}
	if inc.SinceDeploy != 5*time.Minute {
		t.Fatalf("SinceDeploy = %v, want 5m", inc.SinceDeploy)
	}
}

func TestCorrelateWithoutRecentSyncLeavesDeploymentNil(t *testing.T) {
	deps := []Deployment{{Namespace: "shop", At: t0.Add(-time.Hour)}}
	inc := Correlate(alertAt(t0), deps, nil, window())
	if inc.LastDeployment != nil || inc.SinceDeploy != 0 {
		t.Fatalf("want no deployment, got %+v %v", inc.LastDeployment, inc.SinceDeploy)
	}
}

func TestCorrelateRanksErrorTracesFirstThenNearestAndCaps(t *testing.T) {
	traces := []TraceRef{
		{TraceID: "far-ok", Start: t0.Add(90 * time.Second)},
		{TraceID: "near-ok", Start: t0.Add(5 * time.Second)},
		{TraceID: "far-err", Start: t0.Add(-100 * time.Second), Error: true},
		{TraceID: "outside", Start: t0.Add(10 * time.Minute), Error: true},
		{TraceID: "mid-ok", Start: t0.Add(-30 * time.Second)},
	}
	inc := Correlate(alertAt(t0), nil, traces, window())
	var got []string
	for _, tr := range inc.Traces {
		got = append(got, tr.TraceID)
	}
	want := []string{"far-err", "near-ok", "mid-ok"}
	if len(got) != len(want) {
		t.Fatalf("traces = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("traces = %v, want %v", got, want)
		}
	}
}

func TestParsePriorityIsCaseInsensitive(t *testing.T) {
	p, err := ParsePriority("Warning")
	if err != nil || p != PriorityWarning {
		t.Fatalf("ParsePriority = %v, %v", p, err)
	}
	if _, err := ParsePriority("loud"); err == nil {
		t.Fatal("want error for unknown priority")
	}
}
