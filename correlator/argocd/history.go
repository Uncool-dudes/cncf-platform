package argocd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// application is the subset of an Argo CD Application the history needs.
// status.history holds one entry per completed sync, newest last.
type application struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Destination struct {
			Namespace string `json:"namespace"`
		} `json:"destination"`
	} `json:"spec"`
	Status struct {
		History []struct {
			Revision   string    `json:"revision"`
			Revisions  []string  `json:"revisions"`
			DeployedAt time.Time `json:"deployedAt"`
		} `json:"history"`
	} `json:"status"`
}

// DecodeApplications turns an ApplicationList into the deployments recorded
// in each Application's sync history. Multi-source apps report revisions[]
// instead of revision; the first source's revision is used.
func DecodeApplications(r io.Reader) ([]incident.Deployment, error) {
	var list struct {
		Items []application `json:"items"`
	}
	if err := json.NewDecoder(r).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode application list: %w", err)
	}
	var deps []incident.Deployment
	for _, app := range list.Items {
		for _, h := range app.Status.History {
			rev := h.Revision
			if rev == "" && len(h.Revisions) > 0 {
				rev = h.Revisions[0]
			}
			deps = append(deps, incident.Deployment{
				App: app.Metadata.Name, Revision: rev,
				Namespace: app.Spec.Destination.Namespace, At: h.DeployedAt,
			})
		}
	}
	return deps, nil
}

// History lists past syncs from the Kubernetes API, authenticating with the
// pod's service account. Its RBAC is in gitops/manifests/correlator.
type History struct {
	APIServer string
	Namespace string
	Token     string
	HTTP      *http.Client
}

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// InClusterHistory builds a History from the mounted service-account files.
func InClusterHistory(namespace string) (History, error) {
	token, err := os.ReadFile(saDir + "/token")
	if err != nil {
		return History{}, fmt.Errorf("read service account token: %w", err)
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return History{}, fmt.Errorf("read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return History{
		APIServer: "https://kubernetes.default.svc",
		Namespace: namespace,
		Token:     string(token),
		HTTP: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// Deployments returns every sync recorded on the namespace's Applications.
func (h History) Deployments(ctx context.Context) ([]incident.Deployment, error) {
	url := h.APIServer + "/apis/argoproj.io/v1alpha1/namespaces/" + h.Namespace + "/applications"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	resp, err := h.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list applications: status %d", resp.StatusCode)
	}
	return DecodeApplications(resp.Body)
}
