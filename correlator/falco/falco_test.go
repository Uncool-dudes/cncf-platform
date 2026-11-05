package falco

import (
	"errors"
	"strings"
	"testing"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

func TestDecodeAttributesAlertToDeployment(t *testing.T) {
	a, err := Decode(strings.NewReader(`{"rule":"Shell spawned in platform workload","priority":"Warning",
	  "output":"Shell in workload pod","time":"2026-11-05T12:00:00.123456789Z",
	  "output_fields":{"k8s.ns.name":"shop","k8s.pod.name":"checkout-7d9f8b6c5-x2k4p"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Workload != (incident.Workload{Namespace: "shop", Service: "checkout"}) || a.Priority != incident.PriorityWarning {
		t.Fatalf("alert = %+v", a)
	}
	if a.At.Nanosecond() != 123456789 {
		t.Fatalf("lost sub-second precision: %v", a.At)
	}
}

func TestDecodeHostEventHasNoWorkload(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"rule":"x","priority":"Notice","time":"2026-11-05T12:00:00Z","output_fields":{"proc.name":"sshd"}}`))
	if !errors.Is(err, incident.ErrUnknownWorkload) {
		t.Fatalf("want ErrUnknownWorkload, got %v", err)
	}
}

func TestDecodeRejectsUnknownPriorityAndBadJSON(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{"priority":"Loud","time":"2026-11-05T12:00:00Z"}`)); err == nil {
		t.Fatal("want error for unknown priority")
	}
	if _, err := Decode(strings.NewReader(`not json`)); err == nil {
		t.Fatal("want error for malformed body")
	}
}
