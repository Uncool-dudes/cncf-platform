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
up: cluster cilium grafana-secret argocd

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

# One random Grafana admin password. Kept if it already exists.
grafana-secret:
    #!/usr/bin/env bash
    set -euo pipefail
    pass=$(kubectl -n observability get secret grafana-admin -o jsonpath='{.data.admin-password}' 2>/dev/null | base64 -d || true)
    pass=${pass:-$(openssl rand -hex 16)}
    for ns in observability; do
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

down:
    kind delete cluster --name {{cluster}}
