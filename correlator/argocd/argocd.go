// Package argocd decodes Argo CD notification webhooks into deployments.
//
// The body shape is defined by the "correlator" template in
// gitops/values/argocd.yaml; keep the two in sync.
package argocd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

type payload struct {
	App        string    `json:"app"`
	Revision   string    `json:"revision"`
	Namespace  string    `json:"namespace"`
	Phase      string    `json:"phase"`
	FinishedAt time.Time `json:"finishedAt"`
}

// ErrNotSucceeded marks a notification for a sync that did not succeed;
// only completed syncs change what is running.
var ErrNotSucceeded = errors.New("sync did not succeed")

// Decode reads one notification body.
func Decode(r io.Reader) (incident.Deployment, error) {
	var p payload
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return incident.Deployment{}, fmt.Errorf("decode argocd payload: %w", err)
	}
	if p.Phase != "Succeeded" {
		return incident.Deployment{}, fmt.Errorf("%w: phase %q", ErrNotSucceeded, p.Phase)
	}
	return incident.Deployment{App: p.App, Revision: p.Revision, Namespace: p.Namespace, At: p.FinishedAt}, nil
}
