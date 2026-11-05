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
up: cluster cilium

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

down:
    kind delete cluster --name {{cluster}}
