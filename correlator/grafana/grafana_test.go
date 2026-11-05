package grafana

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnnotateReturnsIDAndUpdateTextPatchesIt(t *testing.T) {
	var patched map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "admin" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/annotations":
			_, _ = w.Write([]byte(`{"id":42,"message":"Annotation added"}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/annotations/42":
			_ = json.NewDecoder(r.Body).Decode(&patched)
			_, _ = w.Write([]byte(`{"message":"Annotation patched"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, User: "admin", Password: "pw", HTTP: srv.Client()}

	id, err := c.Annotate(context.Background(), time.Now(), "alert", []string{"falco"})
	if err != nil || id != 42 {
		t.Fatalf("Annotate = %d, %v; want 42", id, err)
	}
	if err := c.UpdateText(context.Background(), id, "alert | trace abc"); err != nil {
		t.Fatalf("UpdateText: %v", err)
	}
	if patched["text"] != "alert | trace abc" {
		t.Fatalf("patched body = %v", patched)
	}
}

func TestAnnotateSurfacesHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Annotate(context.Background(), time.Now(), "x", nil); err == nil {
		t.Fatal("want error on 401")
	}
}
