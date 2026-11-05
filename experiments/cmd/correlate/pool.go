package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
	"github.com/uncool-dudes/cncf-platform/experiments/kube"
)

const trialAnnotation = "experiment.platform.cncf/trial"

// evalNamespace is one podinfo instance in the evaluation pool, deployed by
// its own Argo CD Application named after the namespace. Every sync the
// harness causes changes a pod-template annotation, so it rolls real pods.
type evalNamespace struct {
	name     string
	repoURL  string
	revision string
	// wholeTrial and backendTrial are the current annotation values: one on
	// every resource (kustomize commonAnnotations), one only on backend's
	// pod template. Keeping both lets a backend-only sync leave frontend
	// untouched.
	wholeTrial, backendTrial string
}

func (n *evalNamespace) application() ([]byte, error) {
	patches := []map[string]any{{
		"target": map[string]string{"kind": "VirtualService", "name": "frontend"},
		"patch":  fmt.Sprintf(`[{"op":"replace","path":"/spec/hosts/0","value":"%s.localhost"}]`, n.name),
	}}
	if n.backendTrial != "" {
		patches = append(patches, map[string]any{
			"target": map[string]string{"kind": "Deployment", "name": "backend"},
			"patch": fmt.Sprintf(`[{"op":"add","path":"/spec/template/metadata/annotations/%s","value":"%s"}]`,
				"experiment.platform.cncf~1backend-trial", n.backendTrial),
		})
	}
	kustomize := map[string]any{"namespace": n.name, "patches": patches}
	if n.wholeTrial != "" {
		kustomize["commonAnnotations"] = map[string]string{trialAnnotation: n.wholeTrial}
	}
	return json.Marshal(map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]string{"name": n.name, "namespace": "argocd"},
		"spec": map[string]any{
			"project": "default",
			"source": map[string]any{
				"repoURL":        n.repoURL,
				"targetRevision": n.revision,
				"path":           "examples/podinfo/overlays/eval",
				"kustomize":      kustomize,
			},
			"destination": map[string]string{"server": "https://kubernetes.default.svc", "namespace": n.name},
			"syncPolicy": map[string]any{
				"automated": map[string]bool{"prune": true, "selfHeal": true},
			},
		},
	})
}

type appStatus struct {
	Status struct {
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		Sync struct {
			Status string `json:"status"`
		} `json:"sync"`
		OperationState struct {
			Phase      string    `json:"phase"`
			FinishedAt time.Time `json:"finishedAt"`
			SyncResult struct {
				Revision string `json:"revision"`
			} `json:"syncResult"`
		} `json:"operationState"`
	} `json:"status"`
}

// sync applies the Application and waits for the sync it triggers and the
// rollout of every Deployment, returning that sync as the correlator's
// webhook reports it.
func (n *evalNamespace) sync(ctx context.Context) (incident.Deployment, error) {
	manifest, err := n.application()
	if err != nil {
		return incident.Deployment{}, err
	}
	// finishedAt has second precision.
	applied := time.Now().Truncate(time.Second)
	if err := kube.Apply(ctx, string(manifest)); err != nil {
		return incident.Deployment{}, err
	}

	deadline := time.Now().Add(5 * time.Minute)
	for {
		raw, err := kube.Kubectl(ctx, nil, "-n", "argocd", "get", "application", n.name, "-o", "json")
		if err != nil {
			return incident.Deployment{}, err
		}
		var app appStatus
		if err := json.Unmarshal(raw, &app); err != nil {
			return incident.Deployment{}, err
		}
		op := app.Status.OperationState
		if op.Phase == "Succeeded" && !op.FinishedAt.Before(applied) && app.Status.Sync.Status == "Synced" {
			if err := n.rolledOut(ctx); err != nil {
				return incident.Deployment{}, err
			}
			return incident.Deployment{App: n.name, Revision: op.SyncResult.Revision, Namespace: n.name, At: op.FinishedAt}, nil
		}
		if time.Now().After(deadline) {
			return incident.Deployment{}, fmt.Errorf("application %s: no successful sync after %s (phase %q)", n.name, applied, op.Phase)
		}
		select {
		case <-ctx.Done():
			return incident.Deployment{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func (n *evalNamespace) rolledOut(ctx context.Context) error {
	for _, d := range []string{"frontend", "backend"} {
		if _, err := kube.Kubectl(ctx, nil, "-n", n.name, "rollout", "status", "deploy/"+d, "--timeout=5m"); err != nil {
			return err
		}
	}
	return nil
}

// attack spawns a shell in the workload whose command line carries marker,
// the token that joins the resulting incident to the trial.
func attack(ctx context.Context, namespace, workload, marker string) (time.Time, error) {
	at := time.Now()
	_, err := kube.Kubectl(ctx, nil, "-n", namespace, "exec", "deploy/"+workload, "-c", "podinfo", "--",
		"sh", "-c", "true "+marker)
	return at, err
}
