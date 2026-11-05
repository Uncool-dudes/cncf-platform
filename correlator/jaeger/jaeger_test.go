package jaeger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// One trace per service name, plus one trace reported under both names
// (the sidecar and SDK spans of the same request).
const (
	sidecarResp = `{"data":[
	  {"traceID":"shared","spans":[{"startTime":1000000,"duration":500,"tags":[{"key":"http.status_code","value":503}]}]},
	  {"traceID":"mesh-only","spans":[
	    {"startTime":2000000,"duration":1000,"tags":[]},
	    {"startTime":2000500,"duration":2000,"tags":[{"key":"error","value":false}]}]}]}`
	sdkResp = `{"data":[
	  {"traceID":"shared","spans":[{"startTime":1000100,"duration":100,"tags":[]}]},
	  {"traceID":"sdk-only","spans":[{"startTime":3000000,"duration":10,"tags":[{"key":"otel.status_code","value":"ERROR"}]}]},
	  {"traceID":"empty","spans":[]}]}`
)

func TestFindTracesMergesServiceNamesAndSummarizes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("service") {
		case "checkout.shop":
			_, _ = w.Write([]byte(sidecarResp))
		case "checkout":
			_, _ = w.Write([]byte(sdkResp))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), Limit: 10}

	refs, err := c.FindTraces(context.Background(), incident.Workload{Namespace: "shop", Service: "checkout"}, time.Unix(0, 0), time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]incident.TraceRef{}
	for _, r := range refs {
		byID[r.TraceID] = r
	}
	if len(refs) != 3 {
		t.Fatalf("got %d traces %v, want shared, mesh-only, sdk-only once each", len(refs), byID)
	}
	if !byID["shared"].Error {
		t.Fatal("5xx sidecar span should mark trace failed")
	}
	if m := byID["mesh-only"]; m.Error || m.Duration != 2500*time.Microsecond || !m.Start.Equal(time.UnixMicro(2000000)) {
		t.Fatalf("mesh-only summary = %+v, want 2.5ms from first span start, no error", m)
	}
	if !byID["sdk-only"].Error {
		t.Fatal("OTel ERROR status should mark trace failed")
	}
}

func TestFindTracesSurfacesQueryErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), Limit: 10}
	if _, err := c.FindTraces(context.Background(), incident.Workload{Namespace: "shop", Service: "checkout"}, time.Now(), time.Now()); err == nil {
		t.Fatal("want error on 500")
	}
}
