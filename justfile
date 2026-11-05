# Bootstrap and operate the CNCF platform on kind.
# Everything after `just argocd` is reconciled from Git by Argo CD. These
# recipes cover only what cannot live in Git: the cluster, the CNI, Argo CD
# itself, locally built images, and generated credentials.
#
# Workloads are not part of this repo. See README "Plugging in a workload".

set shell := ["bash", "-euo", "pipefail", "-c"]

cluster := env("KIND_CLUSTER", "platform")
arch    := `docker info --format '{{.Architecture}}' 2>/dev/null | sed 's/aarch64/arm64/;s/x86_64/amd64/'`

# Full bring-up, in dependency order.
up: cluster cilium correlator-image grafana-secret argocd

# kind cluster with the default CNI disabled.
cluster:
    kind get clusters | grep -qx {{cluster}} || kind create cluster --config cluster/kind.yaml

# Cilium must exist before any pod can get an IP, so it is installed here
# rather than by Argo CD.
cilium:
    helm repo add cilium https://helm.cilium.io >/dev/null
    helm upgrade --install cilium cilium/cilium --version 1.20.4 \
      -n kube-system -f cluster/cilium-values.yaml --wait
    cilium status --wait

correlator-image:
    mkdir -p .build
    cd correlator && CGO_ENABLED=0 GOOS=linux GOARCH={{arch}} go build -trimpath -ldflags="-s -w" -o ../.build/correlator ./cmd/correlator
    docker build -q -f correlator/Dockerfile -t platform/correlator:0.1.0 .build >/dev/null
    kind load docker-image --name {{cluster}} platform/correlator:0.1.0

# One random Grafana admin password for otel-lgtm, shared with the correlator
# (which writes annotations). Kept if it already exists.
grafana-secret:
    #!/usr/bin/env bash
    set -euo pipefail
    pass=$(kubectl -n observability get secret grafana-admin -o jsonpath='{.data.admin-password}' 2>/dev/null | base64 -d || true)
    pass=${pass:-$(openssl rand -hex 16)}
    for ns in observability correlator; do
      kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f - >/dev/null
      kubectl -n $ns create secret generic grafana-admin \
        --from-literal=admin-user=admin --from-literal=admin-password="$pass" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    done

# Install Argo CD once, then hand the cluster to the app-of-apps.
argocd:
    helm repo add argo https://argoproj.github.io/argo-helm >/dev/null
    helm upgrade --install argocd argo/argo-cd --version 10.14.0 \
      -n argocd --create-namespace -f gitops/values/argocd.yaml --wait
    # Private-repo access via the local gh token; skipped when gh is not
    # logged in (a public fork needs no credentials).
    if gh auth token >/dev/null 2>&1; then \
      kubectl -n argocd create secret generic repo-cncf-platform \
        --from-literal=type=git \
        --from-literal=url=$(yq '.spec.source.repoURL' gitops/root.yaml) \
        --from-literal=username=x-access-token \
        --from-literal=password="$(gh auth token)" \
        --dry-run=client -o yaml \
        | kubectl label --local -f - argocd.argoproj.io/secret-type=repository -o yaml \
        | kubectl apply -f - >/dev/null; \
    fi
    kubectl apply -f gitops/root.yaml

# Port-forward every UI to localhost.
ui:
    @echo "argocd :8081  grafana :3000  hubble :12000  falco :2802  mailpit :8025  correlator :8090"
    @echo "grafana admin password: $(kubectl -n observability get secret grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d)"
    trap 'kill 0' EXIT; \
    kubectl -n argocd port-forward svc/argocd-server 8081:80 & \
    kubectl -n observability port-forward svc/lgtm 3000:3000 & \
    kubectl -n kube-system port-forward svc/hubble-ui 12000:80 & \
    kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802 & \
    kubectl -n mail port-forward svc/mailpit 8025:8025 & \
    kubectl -n correlator port-forward svc/correlator 8090:8080 & \
    wait

# Simulate an intruder in a workload: attach an ephemeral busybox container
# targeting the app container and run a shell. Fires "Shell spawned in
# platform workload"; the correlator joins it with the namespace's last sync
# and the workload's nearby traces. The Gatekeeper templates inspect only
# containers/initContainers, never spec.ephemeralContainers, so admission
# policy does not stop this - Falco is the control that sees it.
attack namespace workload container="":
    #!/usr/bin/env bash
    set -euo pipefail
    pod=$(kubectl -n {{namespace}} get pod -l app.kubernetes.io/name={{workload}} -o name | head -1)
    target={{container}}
    target=${target:-$(kubectl -n {{namespace}} get $pod -o jsonpath='{.spec.containers[0].name}')}
    kubectl -n {{namespace}} debug "$pod" --image=busybox:1.37 --target="$target" -it -- sh -c 'id; ps; exit 0'

# k6 load from inside the mesh. TARGETS is a JSON file listing in-cluster
# URLs; LABEL names the layer under test (baseline, mesh, mesh+falco, full).
# Toggle layers with Git commits so Argo CD and the correlator record them.
bench label targets:
    mkdir -p bench/results
    kubectl create namespace bench --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl label namespace bench istio-injection=enabled --overwrite >/dev/null
    kubectl -n bench create configmap bench-targets --from-file=targets.json={{targets}} --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl -n bench create configmap k6-script --from-file=bench/health.js --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl -n bench delete job k6 --ignore-not-found >/dev/null
    sed 's/__LABEL__/{{label}}/' bench/job.yaml | kubectl apply -f - >/dev/null
    kubectl -n bench wait --for=condition=complete job/k6 --timeout=15m
    kubectl -n bench logs job/k6 -c k6 | sed -n '/^BENCH_SUMMARY /s/^BENCH_SUMMARY //p' > bench/results/{{label}}.json
    jq . bench/results/{{label}}.json

down:
    kind delete cluster --name {{cluster}}
