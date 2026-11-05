package argocd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeSucceededSync(t *testing.T) {
	d, err := Decode(strings.NewReader(`{"app":"shop","revision":"abc","namespace":"shop","phase":"Succeeded","finishedAt":"2026-11-05T12:00:00Z"}`))
	if err != nil || d.App != "shop" || d.Revision != "abc" || d.Namespace != "shop" || d.At.IsZero() {
		t.Fatalf("Decode = %+v, %v", d, err)
	}
}

func TestDecodeRejectsUnsuccessfulSync(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"app":"shop","phase":"Failed","finishedAt":"2026-11-05T12:00:00Z"}`))
	if !errors.Is(err, ErrNotSucceeded) {
		t.Fatalf("want ErrNotSucceeded, got %v", err)
	}
}

const applicationList = `{"items":[
  {"metadata":{"name":"shop"},"spec":{"destination":{"namespace":"shop"}},
   "status":{"history":[
     {"revision":"r1","deployedAt":"2026-11-05T11:00:00Z","id":0},
     {"revision":"r2","deployedAt":"2026-11-05T11:30:00Z","id":1}]}},
  {"metadata":{"name":"falco"},"spec":{"destination":{"namespace":"falco"}},
   "status":{"history":[{"revisions":["chart-9.2.2","git-abc"],"deployedAt":"2026-11-05T10:00:00Z","id":0}]}},
  {"metadata":{"name":"new"},"spec":{"destination":{"namespace":"new"}},"status":{}}]}`

func TestDecodeApplicationsFlattensHistoryAndMultiSourceRevisions(t *testing.T) {
	deps, err := DecodeApplications(strings.NewReader(applicationList))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 3 {
		t.Fatalf("got %d deployments, want 3: %+v", len(deps), deps)
	}
	if deps[1].Revision != "r2" || deps[1].Namespace != "shop" {
		t.Fatalf("deps[1] = %+v", deps[1])
	}
	if deps[2].Revision != "chart-9.2.2" || deps[2].App != "falco" {
		t.Fatalf("multi-source deps[2] = %+v", deps[2])
	}
}

func TestHistoryListsApplicationsWithBearerToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(applicationList))
	}))
	defer srv.Close()
	h := History{APIServer: srv.URL, Namespace: "argocd", Token: "tok", HTTP: srv.Client()}
	deps, err := h.Deployments(context.Background())
	if err != nil || len(deps) != 3 {
		t.Fatalf("Deployments = %d, %v", len(deps), err)
	}
}
