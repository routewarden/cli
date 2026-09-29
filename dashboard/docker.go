package dashboard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dockerClient talks to the Docker daemon via the Unix socket using plain
// net/http — no external Docker SDK needed. If socket queries fail, it
// falls back to invoking the docker CLI.
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
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// listContainersFromCLI queries running containers using the docker CLI as a resilient fallback.
func listContainersFromCLI() ([]dockerContainer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps cli: %w", err)
	}

	var list []dockerContainer
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Image  string `json:"Image"`
			State  string `json:"State"`
			Labels string `json:"Labels"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		c := dockerContainer{
			ID:     raw.ID,
			Image:  raw.Image,
			State:  raw.State,
			Labels: make(map[string]string),
		}
		if raw.Names != "" {
			for _, n := range strings.Split(raw.Names, ",") {
				clean := strings.TrimPrefix(strings.TrimSpace(n), "/")
				if clean != "" {
					c.Names = append(c.Names, clean)
				}
			}
		}
		if raw.Labels != "" {
			for _, pair := range strings.Split(raw.Labels, ",") {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) == 2 {
					c.Labels[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
		list = append(list, c)
	}
	return list, nil
}

// listContainers returns all running containers, attempting Unix socket first then CLI.
func (d *dockerClient) listContainers() ([]dockerContainer, error) {
	resp, err := d.get("/containers/json?all=false")
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var containers []dockerContainer
		if decodeErr := json.NewDecoder(resp.Body).Decode(&containers); decodeErr == nil && len(containers) > 0 {
			return containers, nil
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	// Resilient fallback to docker CLI
	if cliContainers, cliErr := listContainersFromCLI(); cliErr == nil && len(cliContainers) > 0 {
		return cliContainers, nil
	}

	if err != nil {
		return nil, fmt.Errorf("docker list containers: %w", err)
	}
	return []dockerContainer{}, nil
}

// inspectContainer returns the inspected details of a container by ID or name.
func (d *dockerClient) inspectContainer(idOrName string) (id string, name string, labels map[string]string, err error) {
	// First try direct inspect endpoint: GET /containers/{idOrName}/json
	resp, err := d.get("/containers/" + url.PathEscape(idOrName) + "/json")
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var inspectData struct {
			ID     string `json:"Id"`
			Name   string `json:"Name"`
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&inspectData); err == nil {
			cName := strings.TrimPrefix(inspectData.Name, "/")
			return inspectData.ID, cName, inspectData.Config.Labels, nil
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	// Fallback: list all containers and match by prefix of ID or Name
	containers, listErr := d.listContainers()
	if listErr != nil {
		return "", "", nil, listErr
	}

	cleanTarget := strings.TrimPrefix(idOrName, "/")
	for _, c := range containers {
		cName := containerName(c)
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		if c.ID == idOrName || shortID == idOrName || cName == cleanTarget || strings.EqualFold(cName, cleanTarget) {
			return c.ID, cName, c.Labels, nil
		}
	}

	return "", "", nil, fmt.Errorf("container %q not found", idOrName)
}

// isRouteWardenContainer returns true when the container is likely to emit
// RouteWarden security_event log lines. It checks:
//  1. The label "routewarden=true" or "warden.enabled=true" (explicit opt-in).
//  2. Any label starting with "routewarden" (e.g. routewarden.role, routewarden.json).
//  3. The image name or container name contains a known gateway keyword (traefik, caddy, nginx, openresty, tcp-warden).
//  4. Container name or image has routewarden or rwarden prefix/substring (e.g. rwarden-sandbox-*).
func isRouteWardenContainer(c dockerContainer) bool {
	// Explicit label opt-in
	for k, v := range c.Labels {
		kl := strings.ToLower(k)
		if (kl == "routewarden" || kl == "warden.enabled") && strings.ToLower(v) == "true" {
			return true
		}
		if strings.HasPrefix(kl, "routewarden") || strings.HasPrefix(kl, "warden.") {
			return true
		}
	}
	if isTCPWardenContainer(c) {
		return true
	}
	// Image-name and container-name heuristics
	targets := []string{strings.ToLower(c.Image)}
	for _, n := range c.Names {
		targets = append(targets, strings.ToLower(n))
	}
	for _, target := range targets {
		for _, kw := range []string{"traefik", "caddy", "nginx", "openresty", "tcp-warden"} {
			if strings.Contains(target, kw) {
				return true
			}
		}
		if strings.Contains(target, "routewarden") || strings.Contains(target, "rwarden") || strings.HasPrefix(target, "rwarden-") {
			return true
		}
	}
	return false
}

// isTCPWardenContainer returns true when the container is running tcp-warden.
func isTCPWardenContainer(c dockerContainer) bool {
	for k, v := range c.Labels {
		kl := strings.ToLower(k)
		vl := strings.ToLower(v)
		if (kl == "routewarden.role" || kl == "role") && vl == "tcp-warden" {
			return true
		}
		if (kl == "com.docker.compose.service" || kl == "service") && vl == "tcp-warden" {
			return true
		}
	}
	img := strings.ToLower(c.Image)
	if strings.Contains(img, "tcp-warden") {
		return true
	}
	for _, n := range c.Names {
		nl := strings.ToLower(n)
		if strings.Contains(nl, "tcp-warden") {
			return true
		}
	}
	return false
}

// containerName returns the human-readable name (strips leading slash).
func containerName(c dockerContainer) string {
	if len(c.Names) == 0 {
		if len(c.ID) > 12 {
			return c.ID[:12]
		}
		return c.ID
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// detectPlugin guesses the plugin type from image, labels, or container name.
func detectPlugin(c dockerContainer) string {
	for k, v := range c.Labels {
		kl := strings.ToLower(k)
		if kl == "routewarden.role" && v != "" {
			return v
		}
	}
	targets := []string{strings.ToLower(c.Image)}
	for _, n := range c.Names {
		targets = append(targets, strings.ToLower(n))
	}
	for _, target := range targets {
		switch {
		case strings.Contains(target, "traefik"):
			return "traefik-warden"
		case strings.Contains(target, "caddy"):
			return "caddy-warden"
		case strings.Contains(target, "nginx"), strings.Contains(target, "openresty"):
			return "nginx-warden"
		case strings.Contains(target, "tcp"):
			return "tcp-warden"
		}
	}
	for _, target := range targets {
		if strings.Contains(target, "routewarden") || strings.Contains(target, "rwarden") {
			if strings.Contains(target, "caddy") {
				return "caddy-warden"
			}
			if strings.Contains(target, "nginx") {
				return "nginx-warden"
			}
			if strings.Contains(target, "tcp") {
				return "tcp-warden"
			}
			return "traefik-warden"
		}
	}
	return "unknown"
}

// tailLogs streams the container's stdout/stderr log using tailLines (e.g. 1000)
// and calls onEvent for every parsed SecurityEvent.
// If Docker socket streaming is unavailable, it falls back to the docker CLI.
// It blocks until the context is cancelled.
func (d *dockerClient) tailLogs(ctx context.Context, containerID, containerName, plugin string, tailLines int, onEvent func(SecurityEvent)) error {
	if tailLines <= 0 {
		tailLines = 1000
	}

	// Try Docker HTTP streaming on Unix socket first
	streamCli := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", d.socket)
			},
		},
	}

	url := fmt.Sprintf("http://docker/containers/%s/logs?follow=1&stdout=1&stderr=1&tail=%d&timestamps=0", containerID, tailLines)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		resp, reqErr := streamCli.Do(req)
		if reqErr == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			return parseLogStream(resp.Body, containerName, containerID, plugin, onEvent)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Fallback to docker logs CLI
	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", strconv.Itoa(tailLines), "-f", containerID)
	stdout, pErr := cmd.StdoutPipe()
	if pErr != nil {
		return fmt.Errorf("docker logs pipe: %w", pErr)
	}
	stderr, sErr := cmd.StderrPipe()
	if sErr != nil {
		return fmt.Errorf("docker logs stderr pipe: %w", sErr)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("docker logs start: %w", err)
	}

	go func() {
		_ = parseLogStream(stderr, containerName, containerID, plugin, onEvent)
	}()

	streamErr := parseLogStream(stdout, containerName, containerID, plugin, onEvent)
	_ = cmd.Wait()
	return streamErr
}

// parseLogStream reads from a Docker log stream (multiplexed or plain) and extracts
// RouteWarden security_event JSON lines.
func parseLogStream(r io.Reader, sourceName, sourceID, plugin string, onEvent func(SecurityEvent)) error {
	peekBuf := make([]byte, 4)
	n, err := io.ReadFull(r, peekBuf)
	if n == 0 || err != nil {
		return nil
	}

	var reader io.Reader
	// Docker multiplexing header has stream_type (0x01 or 0x02) followed by 3 zero bytes
	if n == 4 && (peekBuf[0] == 0x01 || peekBuf[0] == 0x02) && peekBuf[1] == 0x00 && peekBuf[2] == 0x00 && peekBuf[3] == 0x00 {
		reader = newDockerFrameReader(io.MultiReader(bytes.NewReader(peekBuf[:n]), r))
	} else {
		reader = io.MultiReader(bytes.NewReader(peekBuf[:n]), r)
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
		!strings.Contains(line, `"path_blocked"`) &&
		!strings.Contains(line, `"plugin_unavailable"`) &&
		!strings.Contains(line, `"upstream_connect_failed"`) &&
		!strings.Contains(line, `"blocked"`) &&
		!strings.Contains(line, `"tarpit"`) &&
		!strings.Contains(line, `"silentDrop"`) &&
		!strings.Contains(line, `"fakeSuccess"`) {
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
		// Fallback: decode raw map to handle type discrepancies like string status or nano timestamps
		var raw map[string]any
		if err2 := json.Unmarshal([]byte(line), &raw); err2 != nil {
			return SecurityEvent{}, false
		}
		if t, ok := raw["type"].(string); ok {
			e.Type = t
		}
		if p, ok := raw["plugin"].(string); ok {
			e.Plugin = p
		}
		if ip, ok := raw["client_ip"].(string); ok {
			e.ClientIP = ip
		}
		if s, ok := raw["service"].(string); ok {
			e.Service = s
		}
		if pr, ok := raw["protocol"].(string); ok {
			e.Protocol = pr
		}
		if m, ok := raw["method"].(string); ok {
			e.Method = m
		}
		if pt, ok := raw["path"].(string); ok {
			e.Path = pt
		}
		if pat, ok := raw["pattern"].(string); ok {
			e.Pattern = pat
		}
		if act, ok := raw["action"].(string); ok {
			e.Action = act
		}
		if r, ok := raw["reason"].(string); ok {
			e.Reason = r
		}
		if cc, ok := raw["country_code"].(string); ok {
			e.CountryCode = cc
		}
		if cn, ok := raw["country_name"].(string); ok {
			e.CountryName = cn
		}
		if fl, ok := raw["flag_emoji"].(string); ok {
			e.FlagEmoji = fl
		}
		if tsStr, ok := raw["timestamp"].(string); ok {
			if parsedT, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
				e.Timestamp = parsedT
			} else if parsedT, err := time.Parse(time.RFC3339, tsStr); err == nil {
				e.Timestamp = parsedT
			}
		}
		if st, ok := raw["status"]; ok {
			switch v := st.(type) {
			case float64:
				e.Status = int(v)
			case string:
				if intV, err := strconv.Atoi(v); err == nil {
					e.Status = intV
				}
			}
		}
		if dur, ok := raw["duration_ms"].(float64); ok {
			e.DurationMs = int64(dur)
		}
		if bi, ok := raw["bytes_in"].(float64); ok {
			e.BytesIn = int64(bi)
		}
		if bo, ok := raw["bytes_out"].(float64); ok {
			e.BytesOut = int64(bo)
		}
	}

	if e.Type != "routewarden_block" && e.Type != "security_event" && e.Reason != "path_blocked" && e.Action != "blocked" && e.Action != "tarpit" && e.Action != "silentDrop" && e.Action != "fakeSuccess" && !strings.Contains(e.Reason, "plugin_unavailable") && !strings.Contains(e.Reason, "upstream_connect_failed") {
		return SecurityEvent{}, false
	}
	if e.Type == "" {
		e.Type = "security_event"
	}
	if e.Action == "" && e.Reason != "" {
		e.Action = "blocked"
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

	if e.EventKind == "" {
		if e.Protocol != "" || e.Service != "" || plugin == "tcp-warden" {
			e.EventKind = "tcp"
		} else {
			e.EventKind = "http"
		}
	}

	return e, true
}

// DockerWatcher discovers RouteWarden containers and tails their logs,
// pushing events into a RingBuffer and broadcasting them to the hub.
type DockerWatcher struct {
	client  *dockerClient
	buf     *RingBuffer
	hub     *Hub
	tail    int

	mu      sync.Mutex
	sources map[string]*Source                 // containerID → Source
	tailing map[string]context.CancelFunc      // containerID -> cancel function
	ctx     context.Context
}

func NewDockerWatcher(socketPath string, buf *RingBuffer, hub *Hub, tail int) *DockerWatcher {
	if tail <= 0 {
		tail = 1000
	}
	return &DockerWatcher{
		client:  newDockerClient(socketPath),
		buf:     buf,
		hub:     hub,
		tail:    tail,
		sources: make(map[string]*Source),
		tailing: make(map[string]context.CancelFunc),
	}
}

// Run starts the watcher. It polls for new containers every 3 s and tails
// logs from all discovered RouteWarden containers. Blocks until ctx is done.
func (w *DockerWatcher) Run(ctx context.Context) {
	w.mu.Lock()
	w.ctx = ctx
	w.mu.Unlock()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	w.discoverAndTail(ctx)

	for {
		select {
		case <-ctx.Done():
			w.mu.Lock()
			for _, cancel := range w.tailing {
				cancel()
			}
			w.tailing = make(map[string]context.CancelFunc)
			w.mu.Unlock()
			return
		case <-ticker.C:
			w.discoverAndTail(ctx)
		}
	}
}

func (w *DockerWatcher) discoverAndTail(ctx context.Context) {
	containers, err := w.client.listContainers()
	if err != nil {
		log.Printf("Docker watcher: unable to list containers on %s: %v", w.client.socket, err)
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	changed := false

	// Prune stale / stopped containers that are no longer running in Docker
	runningIDs := make(map[string]bool)
	for _, c := range containers {
		runningIDs[c.ID] = true
		if len(c.ID) > 12 {
			runningIDs[c.ID[:12]] = true
		}
	}
	for id, s := range w.sources {
		if s.Kind == "docker" && !runningIDs[id] {
			if cancel, isTailing := w.tailing[id]; isTailing {
				cancel()
				delete(w.tailing, id)
			}
			delete(w.sources, id)
			changed = true
		}
	}

	for _, c := range containers {
		if !isRouteWardenContainer(c) {
			continue
		}

		name := containerName(c)

		// Remove any older/stale source with the same container name (e.g. from previous run or recreated container)
		for oldID, existing := range w.sources {
			if existing.Name == name && oldID != c.ID {
				if cancel, isTailing := w.tailing[oldID]; isTailing {
					cancel()
					delete(w.tailing, oldID)
				}
				delete(w.sources, oldID)
				changed = true
			}
		}

		// If this exact container is already actively tailing, skip
		if _, isTailing := w.tailing[c.ID]; isTailing {
			continue
		}

		plugin := detectPlugin(c)
		log.Printf("Docker watcher: monitoring container %s (id: %s, plugin: %s)", name, c.ID[:12], plugin)
		src := &Source{
			ID:     c.ID[:12],
			Name:   name,
			Kind:   "docker",
			Plugin: plugin,
			Status: "live",
		}
		w.sources[c.ID] = src
		changed = true

		tailCtx, cancel := context.WithCancel(ctx)
		w.tailing[c.ID] = cancel

		go w.startTailGoroutine(c.ID, name, plugin, tailCtx)
	}

	if changed {
		w.hub.BroadcastSources(w.Sources())
	}
}

// ClearStopped removes all sources that are in "stopped" or "error" state,
// or whose container is no longer actively running in Docker.
func (w *DockerWatcher) ClearStopped() []Source {
	w.mu.Lock()
	defer w.mu.Unlock()

	aliveIDs := make(map[string]bool)
	if running, err := w.client.listContainers(); err == nil {
		for _, c := range running {
			aliveIDs[c.ID] = true
			if len(c.ID) > 12 {
				aliveIDs[c.ID[:12]] = true
			}
		}
	}

	for id, s := range w.sources {
		isDead := s.Kind == "docker" && len(aliveIDs) > 0 && !aliveIDs[id]
		if s.Status == "stopped" || s.Status == "error" || isDead {
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

// GetContainerConfig looks for the "routewarden.json" label on the specified container.
func (w *DockerWatcher) GetContainerConfig(idOrName string) ConfigResponse {
	w.mu.Lock()
	client := w.client
	w.mu.Unlock()

	if client == nil {
		return ConfigResponse{
			ID:        idOrName,
			HasConfig: false,
			Error:     "Docker client unavailable",
		}
	}

	cID, cName, labels, err := client.inspectContainer(idOrName)
	if err != nil {
		return ConfigResponse{
			ID:        idOrName,
			HasConfig: false,
			Error:     fmt.Sprintf("Container %q not found in Docker", idOrName),
		}
	}

	shortID := cID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	// Look for routewarden.json label
	var rawConfig string
	var labelKey string
	for k, v := range labels {
		kl := strings.ToLower(strings.TrimSpace(k))
		if kl == "routewarden.json" || kl == "routewarden_json" || kl == "routewarden.config" {
			rawConfig = v
			labelKey = k
			break
		}
	}

	if rawConfig == "" {
		return ConfigResponse{
			ID:        shortID,
			Name:      cName,
			Kind:      "docker",
			HasConfig: false,
			Error:     fmt.Sprintf("No routewarden.json label found on container %q.", cName),
			Hint:      "Add LABEL routewarden.json='{...}' in your Dockerfile or --label routewarden.json='{...}' when running the container.",
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rawConfig), &parsed); err != nil {
		return ConfigResponse{
			ID:        shortID,
			Name:      cName,
			Kind:      "docker",
			HasConfig: true,
			LabelKey:  labelKey,
			Raw:       rawConfig,
			Error:     fmt.Sprintf("Invalid JSON in label %q: %v", labelKey, err),
		}
	}

	return ConfigResponse{
		ID:        shortID,
		Name:      cName,
		Kind:      "docker",
		HasConfig: true,
		LabelKey:  labelKey,
		Config:    parsed,
		Raw:       rawConfig,
	}
}

// SourceList returns a thread-safe copy of all sources after synchronizing with running containers.
func (w *DockerWatcher) SourceList() []Source {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Synchronize with currently running Docker containers
	if running, err := w.client.listContainers(); err == nil {
		aliveIDs := make(map[string]bool)
		for _, c := range running {
			aliveIDs[c.ID] = true
			if len(c.ID) > 12 {
				aliveIDs[c.ID[:12]] = true
			}
			// If an active RouteWarden container (including tcp-warden) is running, update or register it
			if isRouteWardenContainer(c) {
				cName := containerName(c)
				plugin := detectPlugin(c)
				if existing, exists := w.sources[c.ID]; exists {
					if existing.Status != "live" {
						existing.Status = "live"
						existing.Details = ""
					}
				} else {
					w.sources[c.ID] = &Source{
						ID:     c.ID[:12],
						Name:   cName,
						Kind:   "docker",
						Plugin: plugin,
						Status: "live",
					}
				}

				if w.ctx != nil {
					if _, isTailing := w.tailing[c.ID]; !isTailing {
						tailCtx, cancel := context.WithCancel(w.ctx)
						w.tailing[c.ID] = cancel
						go w.startTailGoroutine(c.ID, cName, plugin, tailCtx)
					}
				}
			}
		}
		// Prune containers no longer running
		for id, s := range w.sources {
			if s.Kind == "docker" && !aliveIDs[id] {
				if cancel, isTailing := w.tailing[id]; isTailing {
					cancel()
					delete(w.tailing, id)
				}
				delete(w.sources, id)
			}
		}
	}

	return w.Sources()
}

func (w *DockerWatcher) startTailGoroutine(id, name, plugin string, tCtx context.Context) {
	err := w.client.tailLogs(tCtx, id, name, plugin, w.tail, func(e SecurityEvent) {
		e = EnrichGeoIP(e)
		w.buf.Push(e)
		w.hub.Broadcast(e)
	})
	w.mu.Lock()
	delete(w.tailing, id)
	if s, ok := w.sources[id]; ok {
		if err != nil && tCtx.Err() == nil {
			s.Status = "error"
			s.Details = err.Error()
		} else {
			s.Status = "stopped"
		}
		w.hub.BroadcastSources(w.Sources())
	}
	w.mu.Unlock()
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
	for f.rem <= 0 {
		// Read 8-byte frame header
		if _, err := io.ReadFull(f.r, f.buf); err != nil {
			return 0, err
		}
		// Bytes 4-7 are the big-endian payload size
		f.rem = int(binary.BigEndian.Uint32(f.buf[4:8]))
	}
	if len(p) > f.rem {
		p = p[:f.rem]
	}
	n, err := f.r.Read(p)
	f.rem -= n
	return n, err
}
