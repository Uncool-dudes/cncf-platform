package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Summary is the subset of the kubelet Summary API
// (/api/v1/nodes/<node>/proxy/stats/summary) the experiments read. It works
// with no metrics pipeline in the cluster, so every layer, including those
// without observability, is measured the same way.
type Summary struct {
	Pods []struct {
		PodRef struct {
			Namespace string `json:"namespace"`
		} `json:"podRef"`
		Containers []struct {
			Name string `json:"name"`
			CPU  struct {
				UsageCoreNanoSeconds uint64 `json:"usageCoreNanoSeconds"`
			} `json:"cpu"`
			Memory struct {
				WorkingSetBytes uint64 `json:"workingSetBytes"`
			} `json:"memory"`
		} `json:"containers"`
	} `json:"pods"`
}

// Group keys resource usage by namespace and container role.
type Group struct {
	Namespace string
	// Role is "istio-proxy" for sidecars and "app" for every other container.
	Role string
}

// Usage is average CPU over an interval and working-set memory at its end.
type Usage struct {
	CPUCores float64
	MemMiB   float64
}

func roleOf(container string) string {
	if container == "istio-proxy" {
		return "istio-proxy"
	}
	return "app"
}

type counters struct {
	cpuNanos uint64
	memBytes uint64
}

func totals(summaries []Summary) map[Group]counters {
	out := map[Group]counters{}
	for _, s := range summaries {
		for _, p := range s.Pods {
			for _, c := range p.Containers {
				g := Group{Namespace: p.PodRef.Namespace, Role: roleOf(c.Name)}
				t := out[g]
				t.cpuNanos += c.CPU.UsageCoreNanoSeconds
				t.memBytes += c.Memory.WorkingSetBytes
				out[g] = t
			}
		}
	}
	return out
}

// UsageBetween derives per-group usage from two snapshots taken elapsed
// apart. CPU counters are cumulative, so a container that restarted in
// between (counter went backwards) is reported from its new start only.
func UsageBetween(before, after []Summary, elapsed time.Duration) map[Group]Usage {
	b, a := totals(before), totals(after)
	out := make(map[Group]Usage, len(a))
	for g, end := range a {
		delta := end.cpuNanos
		if start := b[g].cpuNanos; start <= end.cpuNanos {
			delta -= start
		}
		out[g] = Usage{
			CPUCores: float64(delta) / float64(elapsed.Nanoseconds()),
			MemMiB:   float64(end.memBytes) / (1 << 20),
		}
	}
	return out
}

// Snapshot reads the Summary API of every node.
func Snapshot(ctx context.Context) ([]Summary, error) {
	names, err := Kubectl(ctx, nil, "get", "nodes", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		return nil, err
	}
	var out []Summary
	for _, n := range strings.Fields(string(names)) {
		raw, err := Kubectl(ctx, nil, "get", "--raw", "/api/v1/nodes/"+n+"/proxy/stats/summary")
		if err != nil {
			return nil, err
		}
		var s Summary
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("node %s summary: %w", n, err)
		}
		out = append(out, s)
	}
	return out, nil
}
