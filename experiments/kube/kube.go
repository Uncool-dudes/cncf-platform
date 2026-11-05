// Package kube drives the cluster through the kubectl on PATH, the same
// tool and context a person running the experiments uses.
package kube

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Kubectl runs kubectl with args and returns stdout. stdin may be nil.
func Kubectl(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stdin = stdin
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kubectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// Apply applies a manifest given as text.
func Apply(ctx context.Context, manifest string) error {
	_, err := Kubectl(ctx, strings.NewReader(manifest), "apply", "-f", "-")
	return err
}

// PortForward forwards localhost:local to a Service's port until ctx ends.
// It returns once the forward accepts connections.
func PortForward(ctx context.Context, namespace, service string, local, remote int) error {
	cmd := exec.CommandContext(ctx, "kubectl", "-n", namespace, "port-forward",
		"svc/"+service, fmt.Sprintf("%d:%d", local, remote))
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	addr := fmt.Sprintf("127.0.0.1:%d", local)
	for range 50 {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port-forward %s/%s: %s never accepted connections", namespace, service, addr)
}
