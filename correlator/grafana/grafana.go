// Package grafana writes correlator events as Grafana annotations, so deploys
// and security alerts appear as markers on the same latency/error panels.
package grafana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Client writes annotations to one Grafana instance.
type Client struct {
	BaseURL  string
	User     string
	Password string
	HTTP     *http.Client
}

// Annotate creates an organisation-wide annotation at a point in time and
// returns its ID for later updates.
func (c Client) Annotate(ctx context.Context, at time.Time, text string, tags []string) (int64, error) {
	var created struct {
		ID int64 `json:"id"`
	}
	err := c.send(ctx, http.MethodPost, "/api/annotations",
		map[string]any{"time": at.UnixMilli(), "text": text, "tags": tags}, &created)
	return created.ID, err
}

// UpdateText replaces an annotation's text, keeping its time and tags.
func (c Client) UpdateText(ctx context.Context, id int64, text string) error {
	return c.send(ctx, http.MethodPatch, "/api/annotations/"+strconv.FormatInt(id, 10),
		map[string]any{"text": text}, nil)
}

func (c Client) send(ctx context.Context, method, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.User, c.Password)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("grafana %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana %s %s: status %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
