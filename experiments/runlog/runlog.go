// Package runlog creates a run's results directory and records the
// environment it ran in, so every result file can be traced to a commit,
// a cluster shape and the flags that produced it.
package runlog

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Dir is one run's results directory.
type Dir string

// New creates <root>/<UTC timestamp>-<name>.
func New(root, name string) (Dir, error) {
	d := filepath.Join(root, time.Now().UTC().Format("20060102T150405Z")+"-"+name)
	return Dir(d), os.MkdirAll(d, 0o755)
}

// Path joins a file name onto the run directory.
func (d Dir) Path(file string) string { return filepath.Join(string(d), file) }

// WriteMeta records the commit, tool versions, cluster shape and params in
// meta.json. Commands that fail are recorded as their error text: a missing
// detail should not abort a multi-hour run.
func (d Dir) WriteMeta(ctx context.Context, params any) error {
	// host_machine is OS, release and architecture only: uname -a would
	// publish the machine's hostname with the results.
	meta := map[string]any{
		"started_at":   time.Now().UTC(),
		"params":       params,
		"git_commit":   run(ctx, "git", "rev-parse", "HEAD"),
		"git_dirty":    run(ctx, "git", "status", "--porcelain") != "",
		"docker":       run(ctx, "docker", "info", "--format", "{{.NCPU}} cpu, {{.MemTotal}} bytes, {{.OperatingSystem}}, kernel {{.KernelVersion}}"),
		"kubectl":      run(ctx, "kubectl", "version", "-o", "json"),
		"nodes":        run(ctx, "kubectl", "get", "nodes", "-o", "wide", "--no-headers"),
		"argocd_apps":  run(ctx, "kubectl", "-n", "argocd", "get", "applications", "--no-headers"),
		"host_machine": run(ctx, "uname", "-srm"),
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.Path("meta.json"), raw, 0o644)
}

func run(ctx context.Context, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "error: " + err.Error() + ": " + strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}
