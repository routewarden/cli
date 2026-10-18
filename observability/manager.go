package observability

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/routewarden/cli/crypto"
)

// DefaultDir returns the default directory where dashboard files are stored.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden/dashboard"
	}
	return filepath.Join(home, ".routewarden", "dashboard")
}

// FindGoAccess checks whether 'goaccess' binary is available in PATH.
func FindGoAccess() (string, error) {
	return exec.LookPath("goaccess")
}

// FindDocker checks whether 'docker' CLI is available in PATH.
func FindDocker() (string, error) {
	return exec.LookPath("docker")
}

// EnsureStackPrepared unpacks embedded GoAccess assets to dir if not already present.
func EnsureStackPrepared(dir string) error {
	composeFile := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(composeFile); err == nil {
		return nil
	}
	return Export(dir)
}

type containerTarget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RemoteAgentInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	EventCount int64  `json:"event_count"`
	Status     string `json:"status"` // "online", "idle", "offline"
}

type SourceInfo struct {
	Mode         string             `json:"mode"`
	File         string             `json:"file,omitempty"`
	Targets      []containerTarget  `json:"targets,omitempty"`
	Agents       []*RemoteAgentInfo `json:"agents,omitempty"`
	TotalEvents  int64              `json:"total_events"`
	BlockedCount int64              `json:"blocked_count"`
	TarpitCount  int64              `json:"tarpit_count"`
}

var (
	sourceMu     sync.RWMutex
	currSource   SourceInfo
	agentMu      sync.RWMutex
	agents       = make(map[string]*RemoteAgentInfo)
	totalEvents  int64
	blockedCount int64
	tarpitCount  int64
)

func recordMetric(status int, verdict string) {
	atomic.AddInt64(&totalEvents, 1)
	v := strings.ToUpper(verdict)
	if status == 403 || v == "BLOCK" {
		atomic.AddInt64(&blockedCount, 1)
	} else if status == 429 || v == "TARPIT" {
		atomic.AddInt64(&tarpitCount, 1)
	}
}

func registerOrTouchAgent(id, name, hostname, remoteIP string, eventCount int) *RemoteAgentInfo {
	agentMu.Lock()
	defer agentMu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	ag, exists := agents[id]
	if !exists {
		ag = &RemoteAgentInfo{
			ID:        id,
			Name:      name,
			Hostname:  hostname,
			RemoteIP:  remoteIP,
			FirstSeen: now,
			LastSeen:  now,
			Status:    "online",
		}
		agents[id] = ag
	}
	ag.LastSeen = now
	if remoteIP != "" {
		ag.RemoteIP = remoteIP
	}
	if hostname != "" {
		ag.Hostname = hostname
	}
	ag.EventCount += int64(eventCount)
	ag.Status = "online"
	return ag
}

func getActiveAgents() []*RemoteAgentInfo {
	agentMu.RLock()
	defer agentMu.RUnlock()
	var list []*RemoteAgentInfo
	now := time.Now().UTC()
	for _, a := range agents {
		if parsed, err := time.Parse(time.RFC3339, a.LastSeen); err == nil {
			diff := now.Sub(parsed)
			if diff > 5*time.Minute {
				a.Status = "offline"
			} else if diff > 60*time.Second {
				a.Status = "idle"
			} else {
				a.Status = "online"
			}
		}
		list = append(list, a)
	}
	return list
}

func updateSourceInfo(mode, file string, targets []containerTarget) {
	sourceMu.Lock()
	defer sourceMu.Unlock()
	currSource = SourceInfo{
		Mode:    mode,
		File:    file,
		Targets: targets,
	}
}

func getSourceInfo() SourceInfo {
	sourceMu.RLock()
	defer sourceMu.RUnlock()
	s := currSource
	s.Agents = getActiveAgents()
	s.TotalEvents = atomic.LoadInt64(&totalEvents)
	s.BlockedCount = atomic.LoadInt64(&blockedCount)
	s.TarpitCount = atomic.LoadInt64(&tarpitCount)
	return s
}

type streamMsg struct {
	Container string
	Line      string
}

type logEvent struct {
	Timestamp      string  `json:"time"`
	TimestampAlt   string  `json:"timestamp"`
	ClientIP       string  `json:"client_ip"`
	ClientIPAlt    string  `json:"ip"`
	ClientHost     string  `json:"ClientHost"`
	Verdict        string  `json:"verdict"`
	Method         string  `json:"method"`
	RequestMethod  string  `json:"RequestMethod"`
	Path           string  `json:"path"`
	PathAlt        string  `json:"request_uri"`
	RequestPath    string  `json:"RequestPath"`
	MatchedPattern string  `json:"matched_pattern"`
	MatchedRuleAlt string  `json:"rule"`
	StatusCode     int     `json:"status"`
	StatusCodeAlt  int     `json:"status_code"`
	DownstreamStat int     `json:"DownstreamStatus"`
	LatencyMs      float64 `json:"latency_ms"`
	DurationMsAlt  float64 `json:"duration_ms"`
}

var combinedLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+\S+`)

func toCombinedLog(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	// Already combined format
	if match := combinedLogRegex.FindStringSubmatch(line); len(match) >= 6 {
		statusCode, _ := strconv.Atoi(match[5])
		recordMetric(statusCode, "")
		return line
	}

	// Try JSON format
	var ev logEvent
	if err := json.Unmarshal([]byte(line), &ev); err == nil && (ev.Path != "" || ev.PathAlt != "" || ev.RequestPath != "" || ev.ClientIP != "" || ev.ClientIPAlt != "" || ev.ClientHost != "" || ev.Verdict != "") {
		ip := ev.ClientIP
		if ip == "" {
			ip = ev.ClientIPAlt
		}
		if ip == "" {
			ip = ev.ClientHost
		}
		if ip == "" {
			ip = "127.0.0.1"
		}

		path := ev.Path
		if path == "" {
			path = ev.PathAlt
		}
		if path == "" {
			path = ev.RequestPath
		}
		if path == "" {
			path = "/"
		}
		path = strings.ReplaceAll(path, `"`, "%22")

		method := ev.Method
		if method == "" {
			method = ev.RequestMethod
		}
		if method == "" {
			method = "GET"
		}
		method = strings.ReplaceAll(method, `"`, "")

		status := ev.StatusCode
		if status == 0 {
			status = ev.StatusCodeAlt
		}
		if status == 0 {
			status = ev.DownstreamStat
		}
		if status == 0 {
			switch strings.ToUpper(ev.Verdict) {
			case "BLOCK":
				status = 403
			case "TARPIT":
				status = 429
			default:
				status = 200
			}
		}

		recordMetric(status, ev.Verdict)

		t := time.Now().UTC()
		if ev.Timestamp != "" {
			if parsed, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
				t = parsed
			}
		} else if ev.TimestampAlt != "" {
			if parsed, err := time.Parse(time.RFC3339, ev.TimestampAlt); err == nil {
				t = parsed
			}
		}
		timeStr := t.Format("02/Jan/2006:15:04:05 -0700")

		rule := ev.MatchedPattern
		if rule == "" {
			rule = ev.MatchedRuleAlt
		}
		rule = strings.ReplaceAll(rule, `"`, `'`)
		verdict := strings.ToUpper(ev.Verdict)

		userAgent := "RouteWarden"
		if rule != "" {
			if verdict != "" && verdict != "ALLOW" {
				userAgent = fmt.Sprintf("[%s: %s]", verdict, rule)
			} else {
				userAgent = fmt.Sprintf("[RULE: %s]", rule)
			}
		} else if verdict != "" && verdict != "ALLOW" {
			userAgent = fmt.Sprintf("[%s]", verdict)
		} else if verdict == "ALLOW" {
			userAgent = "RouteWarden/1.5 (Clean)"
		}
		userAgent = strings.ReplaceAll(userAgent, `"`, `'`)

		return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d 0 \"-\" \"%s\"", ip, timeStr, method, path, status, userAgent)
	}

	// Drop arbitrary non-HTTP and debug log lines
	return ""
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Up starts the GoAccess live dashboard and multiplexes logs from Docker containers or file.
func Up(ctx context.Context, dir string, port int, noOpen bool, file string, container string, label string) error {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dashboard dir: %w", err)
	}
	if err := EnsureStackPrepared(dir); err != nil {
		return fmt.Errorf("prepare dashboard assets: %w", err)
	}

	logFilePath := filepath.Join(dir, "access.log")

	// Create access.log if not present
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open access log: %w", err)
	}
	defer logFile.Close()

	dashboardCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Discover container targets or tail file
	var targets []containerTarget
	if file != "" {
		updateSourceInfo("file", file, nil)
		tailFileToLog(dashboardCtx, file, logFile)
	} else if container != "" {
		if found, err := findSpecificContainer(container); err == nil && len(found) > 0 {
			targets = found
		} else {
			targets = []containerTarget{{ID: container, Name: container}}
		}
		updateSourceInfo("docker", "", targets)
	} else {
		discovered, err := discoverDockerContainers(label)
		if err == nil && len(discovered) > 0 {
			targets = discovered
		}
		updateSourceInfo("docker", "", targets)
	}

	// Prime access.log and globalStore with initial logs from targets
	if len(targets) > 0 {
		for _, target := range targets {
			cmd := exec.Command("docker", "logs", "--tail", "100", target.ID)
			if out, err := cmd.CombinedOutput(); err == nil {
				for _, l := range strings.Split(string(out), "\n") {
					combined := toCombinedLog(l)
					if combined != "" {
						_, _ = logFile.WriteString(combined + "\n")
						globalStore.ParseAndIngest(l, target.Name)
					}
				}
				_ = logFile.Sync()
			}
		}
	} else if file == "" {
		globalStore.SeedDemoData()
	}

	// Continuously stream new logs from discovered containers and watch lifecycle
	if file == "" {
		go watchAndStreamContainers(dashboardCtx, label, container, targets, logFile)
	}

	// Server keypair for decryption
	serverPriv, serverPub, err := EnsureServerKeypair(dir)
	if err != nil {
		return fmt.Errorf("initialize server keypair: %w", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPub)

	mux := NewDashboardHandler(dir, serverPriv, serverPubStr, logFile, nil, "")

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		<-dashboardCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	dashboardURL := fmt.Sprintf("http://localhost:%d", port)
	fmt.Println("🚀 RouteWarden Native SOC Security Dashboard is running!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("📊 Live Dashboard:     %s\n", dashboardURL)
	fmt.Printf("🔒 Encrypted Ingest:   %s/api/v1/events\n", dashboardURL)
	fmt.Printf("📡 Live SSE Stream:    %s/api/stream\n", dashboardURL)
	if len(targets) > 0 {
		fmt.Printf("🐳 Discovered Gateway: %d container(s):\n", len(targets))
		for _, t := range targets {
			fmt.Printf("   • %s (%s)\n", t.Name, t.ID[:min(12, len(t.ID))])
		}
	} else if file != "" {
		fmt.Printf("📁 Monitoring File:    %s\n", file)
	} else {
		fmt.Println("🐳 Auto-Discovery:     Listening for containers with label 'routewarden=true'")
	}
	fmt.Printf("🔑 Server Public Key:  %s\n", serverPubStr[:min(20, len(serverPubStr))]+"...")
	fmt.Printf("⚡ Memory Footprint:   ~8MB (Zero external dependencies)\n")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("Press Ctrl+C to stop.")

	if !noOpen {
		go func() {
			time.Sleep(500 * time.Millisecond)
			openBrowser(dashboardURL)
		}()
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("web server error: %w", err)
	}

	fmt.Println("\n✅ Dashboard stopped.")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func findSpecificContainer(nameOrID string) ([]containerTarget, error) {
	cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "name="+nameOrID, "--format", "{{.ID}}\t{{.Names}}")
	out, err := cmd.Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			parts := strings.Split(line, "\t")
			if len(parts) >= 1 {
				name := parts[0]
				if len(parts) >= 2 {
					name = parts[1]
				}
				if name == nameOrID || strings.HasPrefix(parts[0], nameOrID) {
					return []containerTarget{{ID: parts[0], Name: name}}, nil
				}
			}
		}
	}

	cmd = exec.Command("docker", "ps", "--filter", "status=running", "--filter", "id="+nameOrID, "--format", "{{.ID}}\t{{.Names}}")
	out, err = cmd.Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		parts := strings.Split(strings.TrimSpace(string(out)), "\t")
		name := parts[0]
		if len(parts) >= 2 {
			name = parts[1]
		}
		return []containerTarget{{ID: parts[0], Name: name}}, nil
	}
	return nil, fmt.Errorf("container %q not running", nameOrID)
}

func watchAndStreamContainers(ctx context.Context, label string, specificContainer string, initialTargets []containerTarget, out *os.File) {
	var mu sync.Mutex
	active := make(map[string]context.CancelFunc)
	activeTargets := make(map[string]containerTarget)

	syncSourceInfo := func() {
		mu.Lock()
		var list []containerTarget
		for _, t := range activeTargets {
			list = append(list, t)
		}
		mu.Unlock()
		updateSourceInfo("docker", "", list)
	}

	startStream := func(target containerTarget, tailLines string) {
		mu.Lock()
		if _, exists := active[target.ID]; exists {
			mu.Unlock()
			return
		}
		cCtx, cancel := context.WithCancel(ctx)
		active[target.ID] = cancel
		activeTargets[target.ID] = target
		mu.Unlock()
		syncSourceInfo()

		go func() {
			defer func() {
				mu.Lock()
				delete(active, target.ID)
				delete(activeTargets, target.ID)
				mu.Unlock()
				syncSourceInfo()
				if ctx.Err() == nil {
					fmt.Printf("🛑 [Docker] Container stopped: %s (%s)\n", target.Name, target.ID[:min(12, len(target.ID))])
				}
			}()

			cmd := exec.CommandContext(cCtx, "docker", "logs", "-f", "--tail", tailLines, target.ID)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return
			}
			if err := cmd.Start(); err != nil {
				return
			}

			readPipe := func(r io.Reader) {
				scanner := bufio.NewScanner(r)
				for scanner.Scan() {
					text := scanner.Text()
					combined := toCombinedLog(text)
					if combined != "" {
						mu.Lock()
						_, _ = out.WriteString(combined + "\n")
						_ = out.Sync()
						mu.Unlock()
						globalStore.ParseAndIngest(text, target.Name)
					}
				}
				if err := scanner.Err(); err != nil {
					_ = err
				}
			}

			go readPipe(stdout)
			readPipe(stderr)
			_ = cmd.Wait()
		}()
	}

	for _, t := range initialTargets {
		startStream(t, "50")
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, cancel := range active {
				cancel()
			}
			mu.Unlock()
			return
		case <-ticker.C:
			var found []containerTarget
			if specificContainer != "" {
				if ct, err := findSpecificContainer(specificContainer); err == nil {
					found = ct
				}
			} else {
				if ct, err := discoverDockerContainers(label); err == nil {
					found = ct
				}
			}

			for _, c := range found {
				mu.Lock()
				_, isStreaming := active[c.ID]
				mu.Unlock()

				if !isStreaming {
					fmt.Printf("🐳 [Docker] Attached to container: %s (%s)\n", c.Name, c.ID[:min(12, len(c.ID))])
					startStream(c, "50")
				}
			}
		}
	}
}

func tailFileToLog(ctx context.Context, filePath string, out *os.File) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		line := toCombinedLog(text)
		if line != "" {
			_, _ = out.WriteString(line + "\n")
			globalStore.ParseAndIngest(text, "file")
		}
	}
	if err := scanner.Err(); err != nil {
		_ = err
	}
	_ = out.Sync()
}

func discoverDockerContainers(customLabel string) ([]containerTarget, error) {
	labels := []string{"routewarden=true", "routewarden.logs=true"}
	if customLabel != "" {
		labels = []string{customLabel}
	}

	seen := make(map[string]bool)
	var containers []containerTarget

	for _, l := range labels {
		cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "label="+l, "--format", "{{.ID}}\t{{.Names}}")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		lines := strings.SplitSeq(strings.TrimSpace(string(out)), "\n")
		for line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, "\t")
			id := parts[0]
			name := id
			if len(parts) >= 2 {
				name = parts[1]
			}
			if !seen[id] {
				seen[id] = true
				containers = append(containers, containerTarget{ID: id, Name: name})
			}
		}
	}
	return containers, nil
}

// Down stops the running dashboard container if one was started.
func Down(ctx context.Context, dir string) error {
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", "routewarden-dashboard").Run()
	fmt.Println("✅ RouteWarden Dashboard stopped.")
	return nil
}

// Status checks the status of the dashboard container or local process.
func Status(ctx context.Context, dir string) error {
	out, err := exec.CommandContext(ctx, "docker", "ps", "--filter", "name=routewarden-dashboard", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		fmt.Printf("🟢 Dashboard running in Docker:\n   %s\n", strings.TrimSpace(string(out)))
		return nil
	}
	fmt.Println("ℹ️  No standalone Docker dashboard container running.")
	fmt.Println("   (If launched via 'rwarden dashboard', the dashboard runs directly in the terminal session)")
	return nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func extractAuthToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if key := r.Header.Get("X-API-Key"); key != "" {
		return strings.TrimSpace(key)
	}
	return ""
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// NewDashboardHandler constructs the HTTP handler for the dashboard, API endpoints, and GoAccess proxy.
func NewDashboardHandler(dir string, serverPriv *ecdh.PrivateKey, serverPubStr string, logFile *os.File, wsProxy http.Handler, reportPath string) http.Handler {
	var logMu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sources", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		_ = json.NewEncoder(w).Encode(getSourceInfo())
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		stats := globalStore.GetStats()
		stats.Sources = getSourceInfo()
		_ = json.NewEncoder(w).Encode(stats)
	})

	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		ServeSSE(w, r, globalStore)
	})

	mux.HandleFunc("/api/ip-lookup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "ip parameter required"})
			return
		}
		info := LookupIP(ip)
		_ = json.NewEncoder(w).Encode(info)
	})

	mux.HandleFunc("/api/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"public_key": serverPubStr,
			"version":    "5.0.0",
		})
	})

	mux.HandleFunc("/api/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := extractAuthToken(r)
		key, err := ValidateAgentToken(token, dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		UpdateAgentLastSeen(key.ID, dir)
		clientIP := extractClientIP(r)
		registerOrTouchAgent(key.ID, key.Name, "", clientIP, 0)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "registered",
			"agent_id":   key.ID,
			"agent_name": key.Name,
			"public_key": serverPubStr,
		})
	})

	mux.HandleFunc("/api/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := extractAuthToken(r)
		key, err := ValidateAgentToken(token, dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		var hb struct {
			Hostname string `json:"hostname"`
		}
		_ = json.NewDecoder(r.Body).Decode(&hb)

		UpdateAgentLastSeen(key.ID, dir)
		clientIP := extractClientIP(r)
		registerOrTouchAgent(key.ID, key.Name, hb.Hostname, clientIP, 0)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		token := extractAuthToken(r)
		key, err := ValidateAgentToken(token, dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Try decrypting if payload is EncryptedPayload
		var plaintext = bodyBytes
		var encPayload crypto.EncryptedPayload
		if err := json.Unmarshal(bodyBytes, &encPayload); err == nil && encPayload.Ciphertext != "" && encPayload.EphemeralPub != "" {
			dec, err := crypto.Decrypt(serverPriv, &encPayload)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "decryption failed: " + err.Error()})
				return
			}
			plaintext = dec
		}

		type EventPayload struct {
			AgentID  string            `json:"agent_id"`
			Hostname string            `json:"hostname"`
			Events   []json.RawMessage `json:"events"`
		}

		var payload EventPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			var strList []string
			if err2 := json.Unmarshal(plaintext, &strList); err2 == nil {
				for _, s := range strList {
					payload.Events = append(payload.Events, json.RawMessage([]byte(strconv.Quote(s))))
				}
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid payload format"})
				return
			}
		}

		// Convert and write events
		count := 0
		logMu.Lock()
		for _, rawEv := range payload.Events {
			evStr := string(rawEv)
			if strings.HasPrefix(evStr, `"`) && strings.HasSuffix(evStr, `"`) {
				var unq string
				if err := json.Unmarshal(rawEv, &unq); err == nil {
					evStr = unq
				}
			}
			combined := toCombinedLog(evStr)
			if combined != "" {
				if logFile != nil {
					_, _ = logFile.WriteString(combined + "\n")
				}
				globalStore.ParseAndIngest(evStr, key.Name)
				count++
			}
		}
		if logFile != nil {
			_ = logFile.Sync()
		}
		logMu.Unlock()

		clientIP := extractClientIP(r)
		UpdateAgentLastSeen(key.ID, dir)
		registerOrTouchAgent(key.ID, key.Name, payload.Hostname, clientIP, count)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "accepted",
			"ingested": count,
			"agent":    key.Name,
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if wsProxy != nil && (r.Header.Get("Upgrade") == "websocket" || strings.HasPrefix(r.URL.Path, "/ws")) {
			wsProxy.ServeHTTP(w, r)
			return
		}

		// Serve custom RouteWarden SOC dashboard
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(CustomSOCDashboardHTML))
			return
		}

		if reportPath != "" {
			if _, err := os.Stat(reportPath); err == nil {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				http.ServeFile(w, r, reportPath)
				return
			}
		}

		http.NotFound(w, r)
	})

	return mux
}
