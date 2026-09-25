package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dockerClient talks to the Docker daemon via the Unix socket using plain
// net/http — no external Docker SDK needed. All calls use the HTTP/1.1
// chunked-encoding API that Docker exposes on /var/run/docker.sock.
type dockerClient struct {
	socket string // path to docker.sock, e.g. "/var/run/docker.sock"
	cli    *http.Client
}

func newDockerClient(socket string) *dockerClient {
	return &dockerClient{
		socket: socket,
		cli: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
			Timeout: 5 * time.Second,
		},
	}
}

// get issues an HTTP GET against the Docker Engine API.
func (d *dockerClient) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	return d.cli.Do(req)
}

// dockerContainer is the subset of /containers/json we care about.
type dockerContainer struct {
	ID    string            `json:"Id"`
	Names []string          `json:"Names"`
	Image string            `json:"Image"`
	State string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// listContainers returns all running containers.
func (d *dockerClient) listContainers() ([]dockerContainer, error) {
	resp, err := d.get("/containers/json?all=false")
	if err != nil {
		return nil, fmt.Errorf("docker list containers: %w", err)
	}
	defer resp.Body.Close()
	var containers []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("docker decode containers: %w", err)
	}
	return containers, nil
}

// isRouteWardenContainer returns true when the container is likely to emit
// RouteWarden security_event log lines. It checks:
//  1. The label "routewarden=true" or "warden.enabled=true" (explicit opt-in).
//  2. The image name contains a known gateway keyword.
func isRouteWardenContainer(c dockerContainer) bool {
	// Explicit label opt-in
	for k, v := range c.Labels {
		kl := strings.ToLower(k)
		if (kl == "routewarden" || kl == "warden.enabled") && strings.ToLower(v) == "true" {
			return true
		}
	}
	// Image-name heuristic
	img := strings.ToLower(c.Image)
	for _, kw := range []string{"traefik", "caddy", "nginx", "openresty"} {
		if strings.Contains(img, kw) {
			return true
		}
	}
	return false
}

// containerName returns the human-readable name (strips leading slash).
func containerName(c dockerContainer) string {
	if len(c.Names) == 0 {
		return c.ID[:12]
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// detectPlugin guesses the plugin type from image name.
func detectPlugin(c dockerContainer) string {
	img := strings.ToLower(c.Image)
	switch {
	case strings.Contains(img, "traefik"):
		return "traefik-warden"
	case strings.Contains(img, "caddy"):
		return "caddy-warden"
	case strings.Contains(img, "nginx"), strings.Contains(img, "openresty"):
		return "nginx-warden"
	}
	return "unknown"
}

// tailLogs streams the container's stdout/stderr log from `since` (e.g. "1h")
// and calls onEvent for every parsed SecurityEvent.
// It blocks until the context is cancelled.
func (d *dockerClient) tailLogs(ctx context.Context, containerID, containerName, plugin string, since string, onEvent func(SecurityEvent)) error {
	// Build a streaming log request — no timeout on the client for this one.
	streamCli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", d.socket)
			},
		},
		// No timeout: this is a long-lived streaming connection.
	}

	var sinceParam string
	if since != "" {
		if dur, err := time.ParseDuration(since); err == nil {
			sinceParam = fmt.Sprintf("&since=%d", time.Now().Add(-dur).Unix())
		} else if ts, err := strconv.ParseInt(since, 10, 64); err == nil && ts > 0 {
			sinceParam = fmt.Sprintf("&since=%d", ts)
		}
	}

	url := fmt.Sprintf("http://docker/containers/%s/logs?follow=1&stdout=1&stderr=1&timestamps=0%s", containerID, sinceParam)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := streamCli.Do(req)
	if err != nil {
		return fmt.Errorf("docker logs stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker logs returned status %d: %s", resp.StatusCode, string(body))
	}

	return parseLogStream(resp.Body, containerName, containerID, plugin, onEvent)
}

// parseLogStream reads from a Docker multiplexed log stream and extracts
// RouteWarden security_event JSON lines.
//
// Docker log stream format (when TTY is disabled):
//   [8-byte header: stream_type(1) + 0x00 0x00 0x00 + size(4)] + <payload bytes>
//
// We detect the framing by checking if the first byte is 0x01 or 0x02
// (stdout/stderr multiplexed). If the container uses a TTY the header is
// absent and we fall back to reading plain lines.
func parseLogStream(r io.Reader, sourceName, sourceID, plugin string, onEvent func(SecurityEvent)) error {
	// Peek at first byte to detect framing.
	peekBuf := make([]byte, 1)
	n, err := io.ReadFull(r, peekBuf)
	if n == 0 || err != nil {
		return nil
	}

	var reader io.Reader
	if peekBuf[0] == 0x01 || peekBuf[0] == 0x02 {
		// Multiplexed stream — prepend the consumed byte and use the Docker
		// frame-stripping reader.
		reader = newDockerFrameReader(io.MultiReader(strings.NewReader(string(peekBuf)), r))
	} else {
		// Plain TTY stream — prepend the consumed byte and read lines directly.
		reader = io.MultiReader(strings.NewReader(string(peekBuf)), r)
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if e, ok := parseSecurityEventLine(line, sourceName, sourceID, plugin); ok {
			onEvent(e)
		}
	}
	return scanner.Err()
}

// parseSecurityEventLine attempts to parse a JSON line as a RouteWarden
// security_event or routewarden_block. Returns false if the line is not a security event.
func parseSecurityEventLine(line, sourceName, sourceID, plugin string) (SecurityEvent, bool) {
	if !strings.Contains(line, `"routewarden_block"`) &&
		!strings.Contains(line, `"security_event"`) &&
		!strings.Contains(line, `"path_blocked"`) {
		return SecurityEvent{}, false
	}

	// Extract JSON payload if the line contains extra framing or log prefixes
	start := strings.Index(line, "{")
	end := strings.LastIndex(line, "}")
	if start != -1 && end > start {
		line = line[start : end+1]
	}

	var e SecurityEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		return SecurityEvent{}, false
	}
	if e.Type != "routewarden_block" && e.Type != "security_event" && e.Reason != "path_blocked" {
		return SecurityEvent{}, false
	}

	// Ensure timestamp is set (some versions may omit it)
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Attach source metadata
	e.Source = sourceName
	e.SourceID = sourceID

	// Normalize response mode: in RouteWarden, 'action' holds the mode
	// (e.g. "json", "block", "tarpit", "silentDrop", "fakeSuccess", "gzipBomb", etc.)
	if e.ResponseMode == "" {
		if e.Action != "" {
			e.ResponseMode = e.Action
		} else {
			e.ResponseMode = "block"
		}
	}

	// Normalize plugin gateway if raw plugin name is internal like "warden-8080@file"
	if plugin != "" && (e.Plugin == "" || !strings.Contains(e.Plugin, "-warden")) {
		e.Plugin = plugin
	}

	return e, true
}

// DockerWatcher discovers RouteWarden containers and tails their logs,
// pushing events into a RingBuffer and broadcasting them to the hub.
type DockerWatcher struct {
	client *dockerClient
	buf    *RingBuffer
	hub    *Hub
	since  string // e.g. "1h"

	mu      sync.Mutex
	sources map[string]*Source // containerID → Source
}

func NewDockerWatcher(socketPath string, buf *RingBuffer, hub *Hub, since string) *DockerWatcher {
	return &DockerWatcher{
		client:  newDockerClient(socketPath),
		buf:     buf,
		hub:     hub,
		since:   since,
		sources: make(map[string]*Source),
	}
}

// Run starts the watcher. It polls for new containers every 10 s and tails
// logs from all discovered RouteWarden containers. Blocks until ctx is done.
func (w *DockerWatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	w.discoverAndTail(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.discoverAndTail(ctx)
		}
	}
}

func (w *DockerWatcher) discoverAndTail(ctx context.Context) {
	containers, err := w.client.listContainers()
	if err != nil {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	changed := false

	for _, c := range containers {
		if !isRouteWardenContainer(c) {
			continue
		}

		name := containerName(c)

		// Remove any older/stale source with the same container name (e.g. from previous run or recreated container)
		for oldID, existing := range w.sources {
			if existing.Name == name && oldID != c.ID {
				delete(w.sources, oldID)
				changed = true
			}
		}

		// If this exact container is already actively tailing, skip
		if s, exists := w.sources[c.ID]; exists && s.Status == "live" {
			continue
		}

		plugin := detectPlugin(c)
		src := &Source{
			ID:     c.ID[:12],
			Name:   name,
			Kind:   "docker",
			Plugin: plugin,
			Status: "live",
		}
		w.sources[c.ID] = src
		changed = true

		go func(id, name, plugin string) {
			err := w.client.tailLogs(ctx, id, name, plugin, w.since, func(e SecurityEvent) {
				w.buf.Push(e)
				w.hub.Broadcast(e)
			})
			w.mu.Lock()
			if s, ok := w.sources[id]; ok {
				if err != nil && ctx.Err() == nil {
					s.Status = "error"
					s.Details = err.Error()
				} else {
					s.Status = "stopped"
				}
				w.hub.BroadcastSources(w.Sources())
			}
			w.mu.Unlock()
		}(c.ID, name, plugin)
	}

	if changed {
		w.hub.BroadcastSources(w.Sources())
	}
}

// ClearStopped removes all sources that are in "stopped" or "error" state.
func (w *DockerWatcher) ClearStopped() []Source {
	w.mu.Lock()
	defer w.mu.Unlock()

	for id, s := range w.sources {
		if s.Status == "stopped" || s.Status == "error" {
			delete(w.sources, id)
		}
	}
	sources := w.Sources()
	w.hub.BroadcastSources(sources)
	return sources
}

// Sources returns a snapshot of all known sources (caller must hold mu or
// use the exported method which does not hold the lock — here we assume
// the caller already holds w.mu).
func (w *DockerWatcher) Sources() []Source {
	out := make([]Source, 0, len(w.sources))
	for _, s := range w.sources {
		out = append(out, *s)
	}
	return out
}

// SourceList returns a thread-safe copy of all sources.
func (w *DockerWatcher) SourceList() []Source {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Sources()
}

// --- Docker multiplexed-frame reader ---

// dockerFrameReader strips Docker's 8-byte multiplexing header and exposes
// only the payload bytes as an io.Reader.
type dockerFrameReader struct {
	r   io.Reader
	buf []byte
	rem int
}

func newDockerFrameReader(r io.Reader) *dockerFrameReader {
	return &dockerFrameReader{r: r, buf: make([]byte, 8)}
}

func (f *dockerFrameReader) Read(p []byte) (int, error) {
	for f.rem == 0 {
		// Read 8-byte frame header
		if _, err := io.ReadFull(f.r, f.buf); err != nil {
			return 0, err
		}
		// Bytes 4-7 are the big-endian payload size
		f.rem = int(f.buf[4])<<24 | int(f.buf[5])<<16 | int(f.buf[6])<<8 | int(f.buf[7])
	}
	if len(p) > f.rem {
		p = p[:f.rem]
	}
	n, err := f.r.Read(p)
	f.rem -= n
	return n, err
}
