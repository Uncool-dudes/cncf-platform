package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/uncool-dudes/cncf-platform/experiments/trial"
)

// planter sends steady traffic to every pool namespace through the
// platform's ingress, each request carrying a trace ID chosen here, so the
// traces a correlator should find are known in advance.
type planter struct {
	ingress   string
	interval  time.Duration
	errorRate float64
	log       *slog.Logger

	mu      sync.Mutex
	planted map[string][]trial.PlantedTrace
}

func (p *planter) run(ctx context.Context, namespaces []string, rng *rand.Rand) {
	client := &http.Client{Timeout: 10 * time.Second}
	tick := time.NewTicker(p.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		for _, ns := range namespaces {
			p.send(ctx, client, ns, rng.Float64() < p.errorRate)
		}
	}
}

func (p *planter) send(ctx context.Context, client *http.Client, namespace string, fail bool) {
	traceID, spanID := randomHex(16), randomHex(8)
	method, path, body := http.MethodPost, "/echo", "planted"
	if fail {
		method, path, body = http.MethodGet, "/status/500", ""
	}
	req, err := http.NewRequestWithContext(ctx, method, p.ingress+path, strings.NewReader(body))
	if err != nil {
		return
	}
	req.Host = namespace + ".localhost"
	// W3C Trace Context, sampled; Istio's ingress and podinfo both continue it.
	req.Header.Set("traceparent", "00-"+traceID+"-"+spanID+"-01")
	at := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		p.log.Warn("planted request failed", "namespace", namespace, "err", err)
		return
	}
	resp.Body.Close()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.planted[namespace] = append(p.planted[namespace], trial.PlantedTrace{TraceID: traceID, At: at, Error: fail})
}

// around returns the namespace's planted traces within span of at.
func (p *planter) around(namespace string, at time.Time, span time.Duration) []trial.PlantedTrace {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []trial.PlantedTrace
	for _, t := range p.planted[namespace] {
		if d := t.At.Sub(at); d >= -span && d <= span {
			out = append(out, t)
		}
	}
	return out
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}
