# cncf-platform

A local Kubernetes platform built from CNCF graduated projects. It covers
observability, GitOps and security posture, plus a **correlator** that joins
runtime security alerts with GitOps deploys and distributed traces. That
correlator addresses the cross-tool integration gap from
`Literature_Review_K8s_CNCF.typ`.

The platform is workload-agnostic. Any app opts in with a namespace label.

| Pillar | Tools | Where |
|---|---|---|
| Network / CNI | Cilium 1.20 + Hubble (L3/L4 policy) | `cluster/cilium-values.yaml`, `gitops/manifests/network` |
| Service mesh | Istio 1.30 sidecars + CNI, mesh-wide STRICT mTLS | `gitops/values/istio*.yaml`, `gitops/manifests/istio` |
| Observability | Prometheus, Grafana, OpenTelemetry Collector, Jaeger v2 | `gitops/values/{kube-prometheus-stack,otel-collector,jaeger}.yaml`, `gitops/manifests/observability` |
| GitOps | Argo CD app-of-apps, sync notifications | `gitops/root.yaml`, `gitops/apps`, `gitops/values/argocd.yaml` |
| Admission policy | OPA Gatekeeper: resources, restricted pod security, allowed repos | `gitops/manifests/policy` |
| Runtime security | Falco (modern eBPF, k8smeta) + Falcosidekick | `gitops/values/falco.yaml` |
| Correlator | Falco alert + last Argo CD sync + Jaeger traces into one incident | `correlator/` |

## Data flow

- Workloads emit OTLP to `otel-collector.observability:4317`. Envoy also emits a span for every hop, so uninstrumented services still show up in traces. The collector exports traces to Jaeger and metrics to Prometheus.
- Argo CD notifications POST every successful sync to the correlator.
- Falcosidekick POSTs every Falco alert to the correlator. The correlator:
  1. attributes the alert to a workload (namespace plus Deployment)
  2. finds the latest sync into that namespace (30m lookback)
  3. fetches the workload's traces (±2m, errors first), then refreshes the incident and its annotation once the +2m half has elapsed
  4. records the incident at `GET /v1/incidents`
  5. exports `correlator_incidents_total` and `correlator_deploy_to_alert_seconds`
  6. writes Grafana annotations that show on the "Platform - unified observability and security" dashboard

## Plugging in a workload

The platform needs nothing from a workload except this contract.

1. **Namespace labels and annotations:**
   ```yaml
   metadata:
     labels:
       platform.cncf/workload: "true"   # opts into policy, Falco rules, netpol, dashboard
       istio-injection: enabled
     annotations:
       platform.cncf/allowed-repos: "ghcr.io/me/,docker.io/library/"  # extra image prefixes
   ```
2. **Pods must pass Gatekeeper:**
   - CPU and memory requests, and a memory limit
   - `runAsNonRoot`, with `allowPrivilegeEscalation: false`
   - no added capabilities and no `hostPath`
   - tagged images (not `:latest`) from an allowed repo
3. **Label each Deployment's pods** with `app.kubernetes.io/name: <deployment-name>`, so `just attack` and the correlator resolve the workload.
4. **Optional:**
   - Send OTLP to `otel-collector.observability.svc.cluster.local:4317`.
   - Route edge traffic with a VirtualService on `gateways: [istio-ingress/platform]`, served at `http://localhost:8080`.
   - SMTP goes to `mailpit.mail.svc.cluster.local:1025`.
5. **Extra egress** (a database, an external API on a port other than 443) goes in the workload's own `CiliumNetworkPolicy`. Cilium allow-lists are additive.
6. **Deploy it with an Argo CD `Application`** pointing at the workload's own repo, applied with `kubectl apply`. Every Application's syncs are reported to the correlator automatically.

## Bring-up

Requirements: Docker Desktop with 8 CPU, 16 GB RAM and a 64 GB disk, plus nix with direnv.

```
direnv allow          # dev shell: kind, helm, cilium, istioctl, argocd, k6, just
just up               # cluster, cilium, correlator image, grafana secret, argocd
just ui               # port-forward every UI
just attack <ns> <deployment>      # simulate an intrusion, watch the correlator + dashboard
just bench <label> <targets.json>  # k6 from inside the mesh; results in bench/results/
```

## Limitations

- The Gatekeeper templates don't inspect `spec.ephemeralContainers`, so `kubectl debug` bypasses admission policy. Falco still sees it, which is what `just attack` demonstrates.
- Jaeger stores traces in memory, so restarting it clears history.
- Cilium enforces L3/L4 only. Running L7 policy in both Cilium and Istio causes split-brain, per Cilium's Istio guide.
