// Command correlator joins Falco alerts with Argo CD syncs and Jaeger traces.
// Configuration is environment-only; see gitops/manifests/correlator.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/argocd"
	"github.com/uncool-dudes/cncf-platform/correlator/grafana"
	"github.com/uncool-dudes/cncf-platform/correlator/incident"
	"github.com/uncool-dudes/cncf-platform/correlator/jaeger"
	"github.com/uncool-dudes/cncf-platform/correlator/server"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	httpClient := &http.Client{Timeout: 5 * time.Second}

	srv := &server.Server{
		Traces: jaeger.Client{BaseURL: env("JAEGER_URL", "http://jaeger.observability.svc:16686"), HTTP: httpClient, Limit: 50},
		Annotator: grafana.Client{
			BaseURL:  env("GRAFANA_URL", "http://kps-grafana.observability.svc"),
			User:     env("GRAFANA_USER", "admin"),
			Password: os.Getenv("GRAFANA_PASSWORD"),
			HTTP:     httpClient,
		},
		Window: incident.Window{DeployLookback: 30 * time.Minute, TraceSpan: 2 * time.Minute, MaxTraces: 5},
		Log:    log,
		Keep:   500,
	}

	seedDeployments(srv, log, env("ARGOCD_NAMESPACE", "argocd"))

	addr := env("LISTEN_ADDR", ":8080")
	log.Info("correlator listening", "addr", addr)
	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

// seedDeployments restores sync history lost on restart. Failure is logged,
// not fatal: the correlator still works from new webhooks.
func seedDeployments(srv *server.Server, log *slog.Logger, namespace string) {
	history, err := argocd.InClusterHistory(namespace)
	if err != nil {
		log.Warn("not seeding deployments", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	deps, err := history.Deployments(ctx)
	if err != nil {
		log.Warn("not seeding deployments", "err", err)
		return
	}
	srv.Seed(deps)
	log.Info("seeded deployments from argo cd", "count", len(deps))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
