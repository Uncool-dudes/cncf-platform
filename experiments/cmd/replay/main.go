// Command replay re-scores recorded trials under a grid of correlator
// windows, with no cluster: incident.Correlate is pure, so a trial's recorded
// inputs give the same answer the live correlator would have.
//
//	go run ./cmd/replay results/<run>/trials.jsonl > results/<run>/ablation.csv
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/uncool-dudes/cncf-platform/correlator/incident"
	"github.com/uncool-dudes/cncf-platform/experiments/trial"
)

var (
	lookbacks = []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, 60 * time.Minute, 120 * time.Minute}
	spans     = []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}
)

// maxTraces matches the deployed correlator (correlator/cmd/correlator).
const maxTraces = 5

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: replay <trials.jsonl>")
		os.Exit(2)
	}
	records, err := load(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	out := csv.NewWriter(os.Stdout)
	_ = out.Write([]string{"trial", "scenario", "lookback_s", "span_s", "outcome", "trace_recall", "error_captured"})
	for _, r := range records {
		for _, lb := range lookbacks {
			for _, sp := range spans {
				_ = out.Write(row(r, incident.Window{DeployLookback: lb, TraceSpan: sp, MaxTraces: maxTraces}))
			}
		}
	}
	out.Flush()
	if err := out.Error(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func row(r trial.Record, w incident.Window) []string {
	head := []string{r.ID, string(r.Scenario), secs(w.DeployLookback), secs(w.TraceSpan)}
	inc, ok := trial.Replay(r, w)
	if !ok {
		return append(head, string(trial.Undelivered), "", "")
	}
	ts := trial.ScoreTraces(r.Planted, inc.Traces, inc.Alert.At, w)
	return append(head,
		string(trial.Classify(r.Cause, inc.LastDeployment)),
		strconv.FormatFloat(ts.Recall, 'f', 3, 64),
		strconv.FormatBool(ts.ErrorCaptured))
}

func load(path string) ([]trial.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var records []trial.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var r trial.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		records = append(records, r)
	}
	return records, sc.Err()
}

func secs(d time.Duration) string { return strconv.Itoa(int(d.Seconds())) }
