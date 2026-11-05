package tempo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

var shop = incident.Workload{Namespace: "shop", Service: "checkout"}

// Shapes captured from grafana/otel-lgtm 0.39.0 (Tempo search API):
// startTimeUnixNano is a string, durationMs is omitted when zero, and
// serviceStats carries errorCount only for status=error spans.
const (
	allResp = `{"traces":[
	  {"traceID":"ok-trace","rootServiceName":"checkout.shop","startTimeUnixNano":"1793902883592780002","durationMs":12,
	   "serviceStats":{"checkout.shop":{"spanCount":2}}},
	  {"traceID":"status-error","rootServiceName":"checkout","startTimeUnixNano":"1793902884000000000",
	   "serviceStats":{"checkout":{"spanCount":2,"errorCount":2}}}]}`
	// envoy-503 only appears in the failures search (beyond the first limit).
	failedResp = `{"traces":[
	  {"traceID":"status-error","rootServiceName":"checkout","startTimeUnixNano":"1793902884000000000",
	   "serviceStats":{"checkout":{"spanCount":2,"errorCount":2}}},
	  {"traceID":"envoy-503","rootServiceName":"checkout.shop","startTimeUnixNano":"1793902885000000000","durationMs":3,
	   "serviceStats":{"checkout.shop":{"spanCount":1}}}]}`
)

func TestTraceQLMatchesBothServiceNames(t *testing.T) {
	q := TraceQL(shop, false)
	if q != `{ resource.service.name = "checkout.shop" || resource.service.name = "checkout" }` {
		t.Fatalf("TraceQL = %s", q)
	}
	if f := TraceQL(shop, true); !strings.Contains(f, `span.http.status_code =~ "5.."`) || !strings.HasPrefix(f, "{ (resource") {
		t.Fatalf("failures TraceQL = %s", f)
	}
}

func TestFindTracesMergesSearchesAndMarksFailures(t *testing.T) {
	var gotStart, gotEnd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStart, gotEnd = r.URL.Query().Get("start"), r.URL.Query().Get("end")
		if strings.Contains(r.URL.Query().Get("q"), "status = error") {
			_, _ = w.Write([]byte(failedResp))
			return
		}
		_, _ = w.Write([]byte(allResp))
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), Limit: 20}

	from := time.Unix(1793902800, 0)
	to := time.Unix(1793902900, 500)
	refs, err := c.FindTraces(context.Background(), shop, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if gotStart != "1793902800" || gotEnd != "1793902901" {
		t.Fatalf("start/end = %s/%s, want seconds with end rounded up", gotStart, gotEnd)
	}
	byID := map[string]incident.TraceRef{}
	for _, r := range refs {
		byID[r.TraceID] = r
	}
	if len(refs) != 3 {
		t.Fatalf("got %v, want ok-trace, status-error, envoy-503 once each", byID)
	}
	if byID["ok-trace"].Error || byID["ok-trace"].Duration != 12*time.Millisecond {
		t.Fatalf("ok-trace = %+v", byID["ok-trace"])
	}
	if !byID["status-error"].Error || !byID["envoy-503"].Error {
		t.Fatalf("failures not marked: %+v", byID)
	}
	if !byID["ok-trace"].Start.Equal(time.Unix(0, 1793902883592780002)) {
		t.Fatalf("start = %v", byID["ok-trace"].Start)
	}
}

func TestFindTracesSurfacesSearchErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), Limit: 20}
	if _, err := c.FindTraces(context.Background(), shop, time.Now(), time.Now()); err == nil {
		t.Fatal("want error on 400")
	}
}
