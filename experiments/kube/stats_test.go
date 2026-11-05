package kube

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func summary(t *testing.T, raw string) Summary {
	t.Helper()
	var s Summary
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// Shape as returned by the kubelet; unrelated fields elided.
const before = `{"pods":[{"podRef":{"namespace":"bench-l2-mesh"},"containers":[
  {"name":"podinfo","cpu":{"usageCoreNanoSeconds":1000000000},"memory":{"workingSetBytes":10485760}},
  {"name":"istio-proxy","cpu":{"usageCoreNanoSeconds":2000000000},"memory":{"workingSetBytes":20971520}}]}]}`

const after = `{"pods":[{"podRef":{"namespace":"bench-l2-mesh"},"containers":[
  {"name":"podinfo","cpu":{"usageCoreNanoSeconds":7000000000},"memory":{"workingSetBytes":12582912}},
  {"name":"istio-proxy","cpu":{"usageCoreNanoSeconds":500000000},"memory":{"workingSetBytes":20971520}}]}]}`

func TestUsageBetweenSplitsSidecarsAndAveragesCPU(t *testing.T) {
	got := UsageBetween([]Summary{summary(t, before)}, []Summary{summary(t, after)}, 60*time.Second)

	app := got[Group{Namespace: "bench-l2-mesh", Role: "app"}]
	if math.Abs(app.CPUCores-0.1) > 1e-9 || app.MemMiB != 12 {
		t.Fatalf("app = %+v, want 0.1 cores, 12 MiB", app)
	}
	// The sidecar's counter went backwards: it restarted, so only usage
	// since the restart counts.
	proxy := got[Group{Namespace: "bench-l2-mesh", Role: "istio-proxy"}]
	if math.Abs(proxy.CPUCores-0.5/60) > 1e-9 {
		t.Fatalf("istio-proxy = %+v, want usage since restart", proxy)
	}
}
