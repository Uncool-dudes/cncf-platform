// Command overhead measures what each platform layer costs on one workload:
// k6 latency through two-tier podinfo, plus CPU and memory of every
// namespace, for each layer in bench/layers with Falco on and off.
//
// Cells run in a fresh random order every repetition, so slow drift in the
// host (thermal, Docker VM) spreads across layers instead of biasing one.
// See experiments/README.md for the protocol and threats to validity.
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/uncool-dudes/cncf-platform/experiments/kube"
	"github.com/uncool-dudes/cncf-platform/experiments/runlog"
)

// layer is one directory under bench/layers. meshed layers need a k6
// sidecar: STRICT mTLS rejects plaintext clients.
type layer struct {
	name   string
	meshed bool
}

var layers = []layer{{"l0-cni", false}, {"l1-policy", false}, {"l2-mesh", true}, {"l3-full", true}}

type cell struct {
	layer layer
	falco bool
}

type params struct {
	Reps     int    `json:"reps"`
	Duration string `json:"duration"`
	Warmup   string `json:"warmup"`
	Rate     int    `json:"rate"`
	Falco    string `json:"falco"`
	Seed     uint64 `json:"seed"`
}

type benchSummary struct {
	Requests   int     `json:"requests"`
	FailedRate float64 `json:"failed_rate"`
	LatencyMs  struct {
		Avg, P50, P90, P95, P99, Max float64
	} `json:"latency_ms"`
}

func main() {
	var p params
	repo := flag.String("repo", "..", "cncf-platform checkout")
	results := flag.String("results", "results", "results root")
	flag.IntVar(&p.Reps, "reps", 3, "repetitions of every cell")
	flag.StringVar(&p.Duration, "duration", "3m", "measured k6 duration per cell")
	flag.StringVar(&p.Warmup, "warmup", "30s", "unmeasured k6 run before each cell")
	flag.IntVar(&p.Rate, "rate", 50, "requests per second")
	flag.StringVar(&p.Falco, "falco", "on,off", "Falco states to run: on, off or both")
	flag.Uint64Var(&p.Seed, "seed", uint64(time.Now().UnixNano()), "cell-order shuffle seed")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, log, *repo, *results, p); err != nil {
		log.Error("overhead run failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger, repo, results string, p params) error {
	cells, err := cellsFor(p.Falco)
	if err != nil {
		return err
	}
	job, err := os.ReadFile(filepath.Join(repo, "bench/job.yaml"))
	if err != nil {
		return err
	}
	dir, err := runlog.New(results, "overhead")
	if err != nil {
		return err
	}
	if err := dir.WriteMeta(ctx, p); err != nil {
		return err
	}
	latency, err := newCSV(dir.Path("latency.csv"), "rep", "layer", "falco", "requests", "failed_rate", "avg_ms", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms")
	if err != nil {
		return err
	}
	defer latency.close()
	resources, err := newCSV(dir.Path("resources.csv"), "rep", "layer", "falco", "namespace", "role", "cpu_cores", "mem_mib")
	if err != nil {
		return err
	}
	defer resources.close()

	log.Info("deploying layers")
	if err := deployLayers(ctx, repo); err != nil {
		return err
	}
	if err := prepareBench(ctx, repo); err != nil {
		return err
	}
	// Leave the cluster as Git describes it, whatever happens below.
	defer func() {
		if err := setFalco(context.Background(), repo, true); err != nil {
			log.Error("restoring falco failed; run: kubectl apply -f gitops/root.yaml", "err", err)
		}
	}()

	rng := rand.New(rand.NewPCG(p.Seed, p.Seed))
	falcoOn := true
	for rep := 1; rep <= p.Reps; rep++ {
		rng.Shuffle(len(cells), func(i, j int) { cells[i], cells[j] = cells[j], cells[i] })
		for _, c := range cells {
			if c.falco != falcoOn {
				log.Info("switching falco", "on", c.falco)
				if err := setFalco(ctx, repo, c.falco); err != nil {
					return err
				}
				falcoOn = c.falco
			}
			log.Info("cell", "rep", rep, "layer", c.layer.name, "falco", c.falco)
			sum, usage, err := measure(ctx, string(job), c, p)
			if err != nil {
				return fmt.Errorf("rep %d %s falco=%t: %w", rep, c.layer.name, c.falco, err)
			}
			key := []string{strconv.Itoa(rep), c.layer.name, onOff(c.falco)}
			l := sum.LatencyMs
			latency.write(append(key, strconv.Itoa(sum.Requests), f(sum.FailedRate), f(l.Avg), f(l.P50), f(l.P90), f(l.P95), f(l.P99), f(l.Max)))
			for g, u := range usage {
				resources.write(append(key, g.Namespace, g.Role, f(u.CPUCores), f(u.MemMiB)))
			}
		}
	}
	log.Info("done", "dir", string(dir))
	return nil
}

func cellsFor(falco string) ([]cell, error) {
	var states []bool
	for _, s := range strings.Split(falco, ",") {
		switch s {
		case "on":
			states = append(states, true)
		case "off":
			states = append(states, false)
		default:
			return nil, fmt.Errorf("-falco: unknown state %q", s)
		}
	}
	var cells []cell
	for _, l := range layers {
		for _, on := range states {
			cells = append(cells, cell{l, on})
		}
	}
	return cells, nil
}

func deployLayers(ctx context.Context, repo string) error {
	for _, l := range layers {
		if _, err := kube.Kubectl(ctx, nil, "apply", "-k", filepath.Join(repo, "bench/layers", l.name)); err != nil {
			return err
		}
	}
	for _, l := range layers {
		for _, d := range []string{"frontend", "backend"} {
			if _, err := kube.Kubectl(ctx, nil, "-n", "bench-"+l.name, "rollout", "status", "deploy/"+d, "--timeout=5m"); err != nil {
				return err
			}
		}
	}
	return nil
}

func prepareBench(ctx context.Context, repo string) error {
	ns := `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"bench","labels":{"istio-injection":"enabled"}}}`
	if err := kube.Apply(ctx, ns); err != nil {
		return err
	}
	cm, err := kube.Kubectl(ctx, nil, "-n", "bench", "create", "configmap", "k6-script",
		"--from-file="+filepath.Join(repo, "bench/health.js"), "--dry-run=client", "-o", "yaml")
	if err != nil {
		return err
	}
	return kube.Apply(ctx, string(cm))
}

// measure runs an unmeasured warmup, then the measured k6 run between two
// kubelet snapshots.
func measure(ctx context.Context, job string, c cell, p params) (benchSummary, map[kube.Group]kube.Usage, error) {
	targets, _ := json.Marshal([]map[string]string{{
		"url": "http://frontend.bench-" + c.layer.name + ".svc.cluster.local:9898/echo", "method": "POST", "body": "bench",
	}})
	cm, err := kube.Kubectl(ctx, nil, "-n", "bench", "create", "configmap", "bench-targets",
		"--from-literal=targets.json="+string(targets), "--dry-run=client", "-o", "yaml")
	if err != nil {
		return benchSummary{}, nil, err
	}
	if err := kube.Apply(ctx, string(cm)); err != nil {
		return benchSummary{}, nil, err
	}

	if _, err := runK6(ctx, job, c, p.Warmup, p.Rate, "warmup"); err != nil {
		return benchSummary{}, nil, fmt.Errorf("warmup: %w", err)
	}
	before, err := kube.Snapshot(ctx)
	if err != nil {
		return benchSummary{}, nil, err
	}
	start := time.Now()
	sum, err := runK6(ctx, job, c, p.Duration, p.Rate, c.layer.name)
	if err != nil {
		return benchSummary{}, nil, err
	}
	after, err := kube.Snapshot(ctx)
	if err != nil {
		return benchSummary{}, nil, err
	}
	// The interval includes k6 pod start and teardown at idle, which lowers
	// every group's average equally; latency is unaffected.
	return sum, kube.UsageBetween(before, after, time.Since(start)), nil
}

func runK6(ctx context.Context, job string, c cell, duration string, rate int, label string) (benchSummary, error) {
	if _, err := kube.Kubectl(ctx, nil, "-n", "bench", "delete", "job", "k6", "--ignore-not-found", "--wait=true"); err != nil {
		return benchSummary{}, err
	}
	m := strings.NewReplacer("__LABEL__", label, "__INJECT__", strconv.FormatBool(c.layer.meshed),
		"__DURATION__", duration, "__RATE__", strconv.Itoa(rate)).Replace(job)
	if err := kube.Apply(ctx, m); err != nil {
		return benchSummary{}, err
	}
	d, err := time.ParseDuration(duration)
	if err != nil {
		return benchSummary{}, err
	}
	timeout := "--timeout=" + (d + 5*time.Minute).String()
	if _, err := kube.Kubectl(ctx, nil, "-n", "bench", "wait", "--for=condition=complete", "job/k6", timeout); err != nil {
		return benchSummary{}, err
	}
	logs, err := kube.Kubectl(ctx, nil, "-n", "bench", "logs", "job/k6", "-c", "k6")
	if err != nil {
		return benchSummary{}, err
	}
	return parseSummary(string(logs))
}

func parseSummary(logs string) (benchSummary, error) {
	for _, line := range strings.Split(logs, "\n") {
		raw, ok := strings.CutPrefix(line, "BENCH_SUMMARY ")
		if !ok {
			continue
		}
		var s benchSummary
		return s, json.Unmarshal([]byte(raw), &s)
	}
	return benchSummary{}, errors.New("k6 printed no BENCH_SUMMARY line")
}

// setFalco turns Falco's DaemonSet off by pinning it to no node. Argo CD
// would revert that, so auto-sync is paused on root (which owns the falco
// Application) and on falco first. Turning it on re-applies root from Git,
// which restores both sync policies, and removes the pin directly so the
// wait below does not depend on Argo CD's timing.
func setFalco(ctx context.Context, repo string, on bool) error {
	if on {
		if _, err := kube.Kubectl(ctx, nil, "apply", "-f", filepath.Join(repo, "gitops/root.yaml")); err != nil {
			return err
		}
		// Argo CD may already have removed the pin by the time this runs.
		pin, err := kube.Kubectl(ctx, nil, "-n", "falco", "get", "daemonset", "falco",
			"-o", `jsonpath={.spec.template.spec.nodeSelector.platform\.cncf/bench-no-falco}`)
		if err != nil {
			return err
		}
		if len(pin) > 0 {
			if _, err := kube.Kubectl(ctx, nil, "-n", "falco", "patch", "daemonset", "falco", "--type=json",
				"-p", `[{"op":"remove","path":"/spec/template/spec/nodeSelector/platform.cncf~1bench-no-falco"}]`); err != nil {
				return err
			}
		}
		_, err = kube.Kubectl(ctx, nil, "-n", "falco", "rollout", "status", "daemonset/falco", "--timeout=5m")
		return err
	}
	for _, app := range []string{"root", "falco"} {
		if _, err := kube.Kubectl(ctx, nil, "-n", "argocd", "patch", "application", app, "--type=json",
			"-p", `[{"op":"remove","path":"/spec/syncPolicy/automated"}]`); err != nil {
			return err
		}
	}
	if _, err := kube.Kubectl(ctx, nil, "-n", "falco", "patch", "daemonset", "falco", "--type=merge",
		"-p", `{"spec":{"template":{"spec":{"nodeSelector":{"platform.cncf/bench-no-falco":"true"}}}}}`); err != nil {
		return err
	}
	_, err := kube.Kubectl(ctx, nil, "-n", "falco", "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/name=falco", "--timeout=3m")
	return err
}

type csvFile struct {
	f *os.File
	w *csv.Writer
}

func newCSV(path string, header ...string) (*csvFile, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	c := &csvFile{f: f, w: csv.NewWriter(f)}
	c.write(header)
	return c, nil
}

// write flushes every row so a run interrupted after hours keeps its data.
func (c *csvFile) write(row []string) {
	_ = c.w.Write(row)
	c.w.Flush()
}

func (c *csvFile) close() { _ = c.f.Close() }

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func f(x float64) string { return strconv.FormatFloat(x, 'f', 4, 64) }
