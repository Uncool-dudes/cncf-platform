// Command correlate runs the live correlator evaluation: scripted trials of
// known ground truth (experiments/trial scenarios) against the running
// platform, recording what the correlator reported and every input it saw.
//
// It measures what the pure core cannot: alert delivery, latency to the
// first and refreshed incident, and how many planted traces the trace
// backend surfaces. Window ablations are offline (cmd/replay) on the
// recorded trials.jsonl. See experiments/README.md.
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/argocd"
	"github.com/uncool-dudes/cncf-platform/correlator/incident"
	"github.com/uncool-dudes/cncf-platform/correlator/tempo"
	"github.com/uncool-dudes/cncf-platform/experiments/kube"
	"github.com/uncool-dudes/cncf-platform/experiments/runlog"
	"github.com/uncool-dudes/cncf-platform/experiments/trial"
)

var scenarios = []trial.Scenario{trial.DeployThenAttack, trial.BackToBack, trial.AttackNoDeploy, trial.CrossNamespace, trial.SiblingWorkload}

// replaySpan is the widest trace span cmd/replay scores; traces and planted
// requests are recorded this far either side of each alert.
const replaySpan = 5 * time.Minute

type params struct {
	Trials   int    `json:"trials_per_scenario"`
	Pool     int    `json:"pool"`
	Revision string `json:"revision"`
	// Window must equal the deployed correlator's (correlator/cmd/correlator);
	// it decides quiet-namespace eligibility and live scoring.
	Lookback  string  `json:"lookback"`
	Span      string  `json:"span"`
	MaxTraces int     `json:"max_traces"`
	IndexLag  string  `json:"index_lag"`
	MinDelay  string  `json:"min_delay"`
	MaxDelay  string  `json:"max_delay"`
	Interval  string  `json:"traffic_interval"`
	ErrorRate float64 `json:"traffic_error_rate"`
	Seed      uint64  `json:"seed"`
}

type config struct {
	params
	window                       incident.Window
	indexLag, minDelay, maxDelay time.Duration
}

func main() {
	var p params
	results := flag.String("results", "results", "results root")
	flag.IntVar(&p.Trials, "trials", 10, "trials per scenario")
	flag.IntVar(&p.Pool, "pool", 3, "namespaces that receive syncs, besides eval-quiet")
	flag.StringVar(&p.Revision, "revision", "", "Git commit the eval Applications pin (required)")
	flag.StringVar(&p.Lookback, "lookback", "30m", "correlator DeployLookback")
	flag.StringVar(&p.Span, "span", "2m", "correlator TraceSpan")
	flag.IntVar(&p.MaxTraces, "max-traces", 5, "correlator MaxTraces")
	flag.StringVar(&p.IndexLag, "index-lag", "45s", "correlator IndexLag")
	flag.StringVar(&p.MinDelay, "min-delay", "5s", "shortest sync-to-attack delay")
	flag.StringVar(&p.MaxDelay, "max-delay", "2m", "longest sync-to-attack delay")
	flag.StringVar(&p.Interval, "traffic-interval", "3s", "planted request interval per namespace")
	flag.Float64Var(&p.ErrorRate, "traffic-error-rate", 0.1, "fraction of planted requests that fail")
	flag.Uint64Var(&p.Seed, "seed", uint64(time.Now().UnixNano()), "schedule and delay seed")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := parse(p)
	if err != nil {
		log.Error("bad flags", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, log, *results, cfg); err != nil {
		log.Error("correlate run failed", "err", err)
		os.Exit(1)
	}
}

func parse(p params) (config, error) {
	if p.Revision == "" {
		return config{}, fmt.Errorf("-revision is required: pin the eval Applications to a pushed commit")
	}
	var c config
	c.params = p
	c.window.MaxTraces = p.MaxTraces
	fields := []struct {
		flag  string
		value string
		into  *time.Duration
	}{
		{"lookback", p.Lookback, &c.window.DeployLookback},
		{"span", p.Span, &c.window.TraceSpan},
		{"index-lag", p.IndexLag, &c.indexLag},
		{"min-delay", p.MinDelay, &c.minDelay},
		{"max-delay", p.MaxDelay, &c.maxDelay},
	}
	for _, f := range fields {
		d, err := time.ParseDuration(f.value)
		if err != nil {
			return config{}, fmt.Errorf("-%s: %w", f.flag, err)
		}
		*f.into = d
	}
	return c, nil
}

type harness struct {
	cfg        config
	log        *slog.Logger
	rng        *rand.Rand
	pool       []*evalNamespace
	quiet      *evalNamespace
	quietSince time.Time
	next       int
	planter    *planter
	correlator correlatorClient
}

func run(ctx context.Context, log *slog.Logger, results string, cfg config) error {
	dir, err := runlog.New(results, "correlate")
	if err != nil {
		return err
	}
	if err := dir.WriteMeta(ctx, cfg.params); err != nil {
		return err
	}
	repoURL, err := kube.Kubectl(ctx, nil, "-n", "argocd", "get", "application", "root", "-o", "jsonpath={.spec.source.repoURL}")
	if err != nil {
		return err
	}
	if err := kube.PortForward(ctx, "correlator", "correlator", 18090, 8080); err != nil {
		return err
	}
	if err := kube.PortForward(ctx, "observability", "lgtm", 13200, 3200); err != nil {
		return err
	}

	h := &harness{
		cfg: cfg, log: log, rng: rand.New(rand.NewPCG(cfg.Seed, cfg.Seed)),
		correlator: correlatorClient{baseURL: "http://127.0.0.1:18090", http: &http.Client{Timeout: 10 * time.Second}},
	}
	// A fresh annotation forces a sync even when the namespace survives
	// from an earlier run.
	setup := "setup-" + strconv.FormatInt(time.Now().Unix(), 10)
	newNS := func(name string) *evalNamespace {
		return &evalNamespace{name: name, repoURL: string(repoURL), revision: cfg.Revision, wholeTrial: setup}
	}
	for i := range cfg.Pool {
		h.pool = append(h.pool, newNS("eval-"+strconv.Itoa(i)))
	}
	h.quiet = newNS("eval-quiet")

	log.Info("deploying namespace pool")
	names := []string{h.quiet.name}
	for _, n := range append([]*evalNamespace{h.quiet}, h.pool...) {
		dep, err := n.sync(ctx)
		if err != nil {
			return err
		}
		if n == h.quiet {
			h.quietSince = dep.At
		}
		if n != h.quiet {
			names = append(names, n.name)
		}
	}

	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil {
		return err
	}
	h.planter = &planter{
		ingress: "http://127.0.0.1:8080", interval: interval, errorRate: cfg.ErrorRate, log: log,
		planted: map[string][]trial.PlantedTrace{},
	}
	trafficCtx, stopTraffic := context.WithCancel(ctx)
	defer stopTraffic()
	go h.planter.run(trafficCtx, names, rand.New(rand.NewPCG(cfg.Seed+1, cfg.Seed+1)))

	records := h.runTrials(ctx)
	if ctx.Err() != nil {
		log.Warn("interrupted; recording completed trials", "n", len(records))
	}

	// Let traffic cover the widest replay span after the last alert, then
	// let the trace backend index it.
	if err := sleep(ctx, replaySpan+cfg.indexLag); err != nil && len(records) == 0 {
		return err
	}
	stopTraffic()
	h.recordTraces(context.Background(), records)
	return write(dir, records, cfg)
}

type plan struct {
	id       string
	scenario trial.Scenario
}

func (h *harness) schedule() []plan {
	var plans []plan
	for _, s := range scenarios {
		for i := range h.cfg.Trials {
			plans = append(plans, plan{id: fmt.Sprintf("%s-%02d", s, i), scenario: s})
		}
	}
	h.rng.Shuffle(len(plans), func(i, j int) { plans[i], plans[j] = plans[j], plans[i] })
	return plans
}

// needsQuiet marks scenarios whose alert lands in eval-quiet, which must
// have had no sync within the lookback.
func needsQuiet(s trial.Scenario) bool {
	return s == trial.AttackNoDeploy || s == trial.CrossNamespace
}

// runTrials runs plans in order, deferring quiet-namespace trials until the
// namespace has been quiet for a full lookback. Each trial's incident is
// watched in the background so the next trial starts at once.
func (h *harness) runTrials(ctx context.Context) []trial.Record {
	queue := h.schedule()
	var (
		mu      sync.Mutex
		records []trial.Record
		wg      sync.WaitGroup
	)
	for len(queue) > 0 && ctx.Err() == nil {
		p := queue[0]
		queue = queue[1:]
		if needsQuiet(p.scenario) && !h.quietReady() {
			queue = append(queue, p)
			if allNeedQuiet(queue) {
				wait := time.Until(h.quietSince.Add(h.cfg.window.DeployLookback + time.Minute))
				h.log.Info("waiting for eval-quiet to age past the lookback", "for", wait.Round(time.Second))
				_ = sleep(ctx, wait)
			}
			continue
		}
		r, err := h.prepare(ctx, p)
		if err != nil {
			h.log.Error("trial setup failed; skipping", "trial", p.id, "err", err)
			continue
		}
		h.log.Info("attacked", "trial", r.ID, "namespace", r.Namespace)
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.observe(ctx, &r)
			mu.Lock()
			records = append(records, r)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return records
}

func (h *harness) quietReady() bool {
	return time.Since(h.quietSince) > h.cfg.window.DeployLookback+time.Minute
}

func allNeedQuiet(queue []plan) bool {
	for _, p := range queue {
		if !needsQuiet(p.scenario) {
			return false
		}
	}
	return true
}

func (h *harness) nextPool() *evalNamespace {
	n := h.pool[h.next%len(h.pool)]
	h.next++
	return n
}

func (h *harness) delay() time.Duration {
	span := h.cfg.maxDelay - h.cfg.minDelay
	return h.cfg.minDelay + time.Duration(h.rng.Int64N(int64(span)+1))
}

// prepare causes the scenario's syncs and the attack, returning the trial's
// ground truth.
func (h *harness) prepare(ctx context.Context, p plan) (trial.Record, error) {
	r := trial.Record{ID: p.id, Scenario: p.scenario, Workload: "frontend", Marker: "trial-" + p.id}
	var target *evalNamespace
	switch p.scenario {
	case trial.DeployThenAttack, trial.BackToBack:
		target = h.nextPool()
		if p.scenario == trial.BackToBack {
			target.wholeTrial = p.id + "-first"
			if _, err := target.sync(ctx); err != nil {
				return r, err
			}
			if err := sleep(ctx, 20*time.Second); err != nil {
				return r, err
			}
		}
		target.wholeTrial = p.id
		cause, err := target.sync(ctx)
		if err != nil {
			return r, err
		}
		r.Cause = &cause
	case trial.CrossNamespace:
		other := h.nextPool()
		other.wholeTrial = p.id
		if _, err := other.sync(ctx); err != nil {
			return r, err
		}
		target = h.quiet
	case trial.SiblingWorkload:
		target = h.nextPool()
		target.backendTrial = p.id
		if _, err := target.sync(ctx); err != nil {
			return r, err
		}
	case trial.AttackNoDeploy:
		target = h.quiet
	}
	r.Namespace = target.name
	if p.scenario != trial.AttackNoDeploy {
		if err := sleep(ctx, h.delay()); err != nil {
			return r, err
		}
	}
	at, err := attack(ctx, r.Namespace, r.Workload, r.Marker)
	if err != nil {
		return r, err
	}
	r.AttackAt = at
	return r, nil
}

// observe waits for the trial's incident and records the deployments the
// correlator could have known when the alert arrived.
func (h *harness) observe(ctx context.Context, r *trial.Record) {
	settle := h.cfg.window.TraceSpan + h.cfg.indexLag + 20*time.Second
	obs, err := h.correlator.watch(ctx, r.Marker, time.Minute, settle)
	if err != nil {
		h.log.Error("watching incident failed", "trial", r.ID, "err", err)
	}
	if raw, err := kube.Kubectl(ctx, nil, "-n", "argocd", "get", "applications", "-o", "json"); err == nil {
		r.Deployments, _ = argocd.DecodeApplications(bytes.NewReader(raw))
	}
	if !obs.delivered {
		h.log.Warn("incident never arrived", "trial", r.ID)
		return
	}
	alert, err := obs.first.alert()
	if err != nil {
		h.log.Error("decoding incident failed", "trial", r.ID, "err", err)
		return
	}
	r.Alert = &alert
	r.ReportedCause = obs.final.reportedCause()
	r.ReportedTraces = obs.final.reportedTraces()
	r.FirstSeenAt, r.FinalSeenAt = obs.firstSeen, obs.finalSeenAt
	h.log.Info("observed", "trial", r.ID, "outcome", trial.Classify(r.Cause, r.ReportedCause))
}

// recordTraces stores, per trial, the traces the backend holds and the
// requests planted within replaySpan of the alert.
func (h *harness) recordTraces(ctx context.Context, records []trial.Record) {
	backend := tempo.Client{BaseURL: "http://127.0.0.1:13200", HTTP: &http.Client{Timeout: 30 * time.Second}, Limit: 2000}
	for i := range records {
		r := &records[i]
		at := r.AttackAt
		if r.Alert != nil {
			at = r.Alert.At
		}
		r.Planted = h.planter.around(r.Namespace, at, replaySpan)
		w := incident.Workload{Namespace: r.Namespace, Service: r.Workload}
		traces, err := backend.FindTraces(ctx, w, at.Add(-replaySpan), at.Add(replaySpan))
		if err != nil {
			h.log.Error("recording traces failed", "trial", r.ID, "err", err)
		}
		r.Traces = traces
	}
}

func write(dir runlog.Dir, records []trial.Record, cfg config) error {
	var jsonl bytes.Buffer
	enc := json.NewEncoder(&jsonl)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	if err := os.WriteFile(dir.Path("trials.jsonl"), jsonl.Bytes(), 0o644); err != nil {
		return err
	}

	var table strings.Builder
	out := csv.NewWriter(&table)
	_ = out.Write([]string{"trial", "scenario", "namespace", "outcome", "detect_s", "deliver_s", "final_s", "trace_recall", "error_captured"})
	for _, r := range records {
		row := []string{r.ID, string(r.Scenario), r.Namespace}
		if r.Alert == nil {
			_ = out.Write(append(row, string(trial.Undelivered), "", "", "", "", ""))
			continue
		}
		ts := trial.ScoreTraces(r.Planted, r.ReportedTraces, r.Alert.At, cfg.window)
		_ = out.Write(append(row,
			string(trial.Classify(r.Cause, r.ReportedCause)),
			secs(r.Alert.At.Sub(r.AttackAt)),
			secs(r.FirstSeenAt.Sub(r.AttackAt)),
			secs(r.FinalSeenAt.Sub(r.Alert.At)),
			strconv.FormatFloat(ts.Recall, 'f', 3, 64),
			strconv.FormatBool(ts.ErrorCaptured)))
	}
	out.Flush()
	return os.WriteFile(dir.Path("trials.csv"), []byte(table.String()), 0o644)
}

func secs(d time.Duration) string { return strconv.FormatFloat(d.Seconds(), 'f', 3, 64) }
