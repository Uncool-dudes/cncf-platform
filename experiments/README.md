# Experiments

These experiments evaluate the platform against research gap 1 of
`Literature_Review_K8s_CNCF.typ`: few studies *measure* alert correlation
or the combined overhead of running observability, GitOps and security
stacks together.

Everything runs from this repository on the kind cluster from `just up`.
Each run writes `results/<UTC timestamp>-<study>/`. That directory holds the
raw CSV/JSONL files and `meta.json`, which records the commit, dirty flag,
Docker VM size, node list, Argo CD app states and every parameter. Commit the
results directories you report.

| Step | Command |
|---|---|
| Live correlator trials | `just correlate [-trials N] [-pool P] ...` |
| Window ablation (offline) | `just replay <run>` |
| Overhead matrix | `just overhead [-reps N] [-duration 3m] [-falco on,off]` |
| Tables and plots | `just report <run>` writes `summary.md` and PNGs into the run |

## Study 1: correlator evaluation

### Questions

- **RQ1:** Does the correlator attribute a runtime alert to the sync that
  caused it, and to no sync when none did?
- **RQ2:** How long do detection, delivery and the trace refresh take?
- **RQ3:** Does the incident surface the workload's relevant traces,
  especially failed ones?
- **RQ4:** How do RQ1 and RQ3 depend on the window parameters (deploy
  lookback, trace half-window)?

### Setup

- The pool is `eval-0..eval-P-1` plus `eval-quiet`, each a two-tier podinfo
  (`examples/podinfo/overlays/eval`).
- Each namespace has its own Argo CD Application, which the harness pins to
  the pushed `HEAD`.
- A planter sends one request every `-traffic-interval` to every namespace
  through the platform ingress. Each request carries a W3C `traceparent`
  chosen by the harness. `-traffic-error-rate` of them hit `/status/500`.
  The traces the correlator should find are therefore known in advance.
- A sync is caused by changing a pod-template annotation through the
  Application. It rolls real pods and Argo CD sends the real webhook.
- An attack is `kubectl exec ... sh -c 'true trial-<id>'`. That fires the
  platform rule "Shell spawned in platform workload". The marker in the
  command line reaches the incident through Falco's output and joins the
  incident to its trial.

### Scenarios and ground truth

| Scenario | What the harness does | True cause |
|---|---|---|
| `deploy-then-attack` | sync namespace, wait U[min,max] delay, attack | that sync |
| `back-to-back` | sync, wait 20 s, sync again, delay, attack | the second sync |
| `attack-no-deploy` | attack `eval-quiet`, which has had no sync for longer than the lookback | none |
| `cross-namespace` | sync another namespace, delay, attack `eval-quiet` | none |
| `sibling-workload` | sync that changes only `backend`, delay, attack `frontend` in the same namespace | none |

- Trials are shuffled with `-seed`.
- Quiet-namespace trials wait until `eval-quiet` has aged past the lookback.
- `sibling-workload` is a known limitation, measured on purpose. The
  correlator matches syncs by namespace, not by the workload a sync changed.

### Metrics

- **Outcome:** `hit`, `wrong-deploy`, `miss`, `correct-none`, `spurious` or
  `undelivered` (see `trial/score.go`). Attribution is correct when the
  outcome is `hit` or `correct-none`.
- **`detect_s`:** alert time (Falco) minus attack time (harness).
- **`deliver_s`:** time until the incident is visible at `GET /v1/incidents`.
- **`final_s`:** alert to the last change of its trace list, i.e. the
  post-alert refresh.
- **Trace recall:** captured planted traces divided by
  `min(planted in window, MaxTraces)`.
- **Error captured:** whether a planted failed trace in the window was reported.

### Replay

- The recorded `trials.jsonl` holds every input the correlator saw:
  - the alert
  - the Argo CD sync history at the time
  - the backend's traces within ±5 min
- `incident.Correlate` is pure, so `cmd/replay` re-scores each trial over a
  grid of lookbacks (1 min to 2 h) and spans (30 s to 5 min) with no cluster.

### Manual triage baseline (human, not automated)

The correlator's practical claim is a shorter path to root cause, and only
people can measure that.

1. Recruit at least 3 participants who know Kubernetes.
2. Show each one a Falco alert from a `deploy-then-attack` trial.
3. Ask: which sync preceded it, and which failing request is nearby?
4. **Baseline condition:** Falcosidekick UI, Argo CD UI and Grafana Explore
   (Tempo), used separately.
5. **Treatment condition:** the correlator's incident and the unified
   dashboard's annotations.
6. Record time to answer, correctness, and number of UI switches.
7. Counterbalance which condition each participant does first.

## Study 2: overhead matrix

### Layers

All layers run the same two-tier podinfo; `bench/layers` holds the
overlays. k6 sends POST `/echo` from the `bench` namespace. That request
crosses both tiers.

| Layer | Adds | k6 sidecar |
|---|---|---|
| `l0-cni` | nothing: Cilium as CNI only, no policy | no |
| `l1-policy` | platform workload label: Cilium baseline policy, Gatekeeper, Falco workload rules | no |
| `l2-mesh` | Istio sidecars with STRICT mTLS, tracing sampled at 0% | yes |
| `l3-full` | 100% tracing from Envoy and the podinfo SDK | yes |

Each layer runs with Falco on and off. Off means auto-sync is paused and the
DaemonSet is pinned to no node; on restores it from Git.

### Measurement

- For each cell: an unmeasured warmup, then a fixed-arrival-rate run
  (`-rate` req/s for `-duration`).
- k6 reports p50, p90, p95 and p99 latency and the failure rate.
- CPU and memory come from the kubelet Summary API, so layers without the
  observability stack are measured identically:
  - CPU is cumulative core-seconds over the run.
  - Memory is the working set at the end.
  - Both are grouped by namespace and split into app versus `istio-proxy`.
- Cell order is reshuffled every repetition so host drift spreads across
  layers.

## Integration defects found by running it

The first live bring-up and the harness smoke run found four defects
that every unit test had passed. None of them shows when each tool is evaluated alone.

1. **Gatekeeper allowed-repos versus the Istio hub.** The constraint
   allowed `docker.io/istio/`, but Istio 1.30 injects
   `registry.istio.io/release/proxyv2`. Every meshed pod in a platform
   namespace was denied admission, including the correlator.
2. **Sync attribution needs `spec.destination.namespace`.** An Application
   that sets its namespace only through kustomize reported syncs with an
   empty namespace, so no alert ever matched them.
3. **Notification deduplication per revision.** Argo CD's `oncePer:
   syncResult.revision` suppressed webhooks for a second sync of the same
   commit. That covers parameter changes, manual syncs and rollbacks. The
   correlator then reported the previous sync: a wrong attribution.

4. **Trace lookup leaked across namespaces.** The Tempo query matched the
   OTel SDK's bare service name (`frontend`), which every namespace running
   the same app shares. Incidents then listed other namespaces' failed
   requests and none of their own. The smoke run of this harness found it:
   two namespaces reported identical trace IDs.

## Threats to validity

### Internal

- **One host for everything.** The cluster, k6 and the harness share one
  4-CPU Docker Desktop VM. k6 competes with the system under test, so
  absolute latencies are inflated. Compare layers, not absolute numbers.
- **Cluster size.** kind with one control plane and one worker. All
  workloads share a node and its kernel, and Falco watches all of them.
- **Clocks.**
  - Falco timestamps come from the VM kernel; the harness uses the macOS
    clock. Their offset adds to `detect_s`.
  - Argo CD `finishedAt` has one-second precision.
  - Sync identity is matched within ±2 s.
- **Ground truth is temporal, not causal.** "Cause" is the sync the harness
  made before the attack. A real alert can follow a sync by coincidence, and
  the correlator, like this ground truth, cannot tell.
- **Replay assumptions.**
  - It assumes the delivered webhooks equal Argo CD's history, so a lost
    webhook would not appear in replay. Live outcomes measure that
    separately.
  - Recorded traces come from one Tempo search with a 2000 limit.
- **Concurrency.** Trials overlap: a trial's incident is watched while the
  next one runs, in another namespace.
- **Overhead CPU interval.** The interval includes k6 pod start and stop at
  idle. That lowers every group's average equally.

### External

- podinfo is a small Go service, unlike real workloads.
- Results cover one version set, pinned by `flake.lock` and the charts
  under `gitops/`.
- otel-lgtm is a single-pod demo backend. Tempo's indexing lag on it (about
  30 s) drives `final_s`.
- Only one attack technique (shell spawn) and one Falco rule are exercised.
- The cluster is a single cluster with no multi-tenancy (research gap 5).

### Construct

- The baseline layer still runs Cilium, because it is the CNI. "No platform"
  means "Cilium without policy".
- Trace recall counts planted traffic only. The correlator ranks failed
  traces first, so recall is capped by `MaxTraces`, and "error captured" is
  the more meaningful measure.
