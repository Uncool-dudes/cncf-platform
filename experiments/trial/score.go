package trial

import (
	"slices"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
)

// Outcome compares the deploy a correlator reported against the true cause.
type Outcome string

const (
	// Hit: reported the causing sync.
	Hit Outcome = "hit"
	// WrongDeploy: a sync caused the alert, a different one was reported.
	WrongDeploy Outcome = "wrong-deploy"
	// Miss: a sync caused the alert, none was reported.
	Miss Outcome = "miss"
	// CorrectNone: no sync caused the alert and none was reported.
	CorrectNone Outcome = "correct-none"
	// Spurious: no sync caused the alert, one was reported anyway.
	Spurious Outcome = "spurious"
	// Undelivered: the alert never reached the correlator.
	Undelivered Outcome = "undelivered"
)

// syncTolerance absorbs the gap between the time Argo CD's notification
// reports for a sync and the time its history records for the same sync.
const syncTolerance = 2 * time.Second

// SameSync reports whether two deployments describe one Argo CD sync.
func SameSync(a, b incident.Deployment) bool {
	gap := a.At.Sub(b.At)
	return a.App == b.App && a.Revision == b.Revision && gap <= syncTolerance && gap >= -syncTolerance
}

// Classify scores a reported deploy against the true cause.
func Classify(cause, reported *incident.Deployment) Outcome {
	switch {
	case cause == nil && reported == nil:
		return CorrectNone
	case cause == nil:
		return Spurious
	case reported == nil:
		return Miss
	case SameSync(*cause, *reported):
		return Hit
	}
	return WrongDeploy
}

// TraceScore measures how well reported traces cover the planted ones that
// fall inside the trace window.
type TraceScore struct {
	// Recall is captured planted traces over min(eligible, MaxTraces); 1
	// when nothing was eligible.
	Recall float64
	// ErrorCaptured is true when an eligible planted error trace was
	// reported, or none was eligible.
	ErrorCaptured bool
}

// ScoreTraces compares reported traces with the planted ones within w of at.
func ScoreTraces(planted []PlantedTrace, reported []incident.TraceRef, at time.Time, w incident.Window) TraceScore {
	from, to := w.TraceRange(at)
	ids := make([]string, len(reported))
	for i, t := range reported {
		ids[i] = t.TraceID
	}

	var eligible, captured int
	errorEligible, errorCaptured := false, false
	for _, p := range planted {
		if p.At.Before(from) || p.At.After(to) {
			continue
		}
		eligible++
		hit := slices.Contains(ids, p.TraceID)
		if hit {
			captured++
		}
		if p.Error {
			errorEligible = true
			errorCaptured = errorCaptured || hit
		}
	}

	score := TraceScore{Recall: 1, ErrorCaptured: !errorEligible || errorCaptured}
	if denom := min(eligible, w.MaxTraces); denom > 0 {
		score.Recall = float64(min(captured, denom)) / float64(denom)
	}
	return score
}

// Replay re-runs the correlator's pure core on a trial's recorded inputs
// under window w. ok is false when the alert never reached the correlator.
func Replay(r Record, w incident.Window) (inc incident.Incident, ok bool) {
	if r.Alert == nil {
		return incident.Incident{}, false
	}
	return incident.Correlate(*r.Alert, r.Deployments, r.Traces, w), true
}
