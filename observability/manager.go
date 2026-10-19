package observability

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
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

// Version represents the active version of RouteWarden Observability & Dashboard engine.
var Version = "5.0.2"

// DefaultDir returns the default directory where dashboard files are stored.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".routewarden/dashboard"
	}
	return filepath.Join(home, ".routewarden", "dashboard")
}

// FindDocker checks whether 'docker' CLI is available in PATH.
func FindDocker() (string, error) {
	return exec.LookPath("docker")
}

// EnsureStackPrepared unpacks embedded dashboard assets to dir if not already present.
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
	sourceMu       sync.RWMutex
	currSource     SourceInfo
	agentMu        sync.RWMutex
	agents         = make(map[string]*RemoteAgentInfo)
	totalEvents    int64
	blockedCount   int64
	tarpitCount    int64
	dashboardLogMu sync.Mutex
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
		if parsed, err := time.Parse(time.RFC3339Nano, a.LastSeen); err == nil {
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

		t := time.Now().UTC()
		tsRaw := ev.Timestamp
		if tsRaw == "" {
			tsRaw = ev.TimestampAlt
		}
		if tsRaw != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, tsRaw); err == nil {
				t = parsed
			} else if parsed, err := time.Parse("2006-01-02 15:04:05", tsRaw); err == nil {
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

// Up starts the live SOC security dashboard and multiplexes logs from Docker containers or file.
// Optional auth ("user:pass") and host interface ("127.0.0.1" or "0.0.0.0") can be provided in options.
func Up(ctx context.Context, dir string, port int, noOpen bool, file string, container string, label string, options ...string) error {
	var authStr string
	var hostStr string
	if len(options) > 0 {
		authStr = strings.TrimSpace(options[0])
	}
	if len(options) > 1 {
		hostStr = strings.TrimSpace(options[1])
	}
	if authStr == "" {
		authStr = strings.TrimSpace(os.Getenv("RW_DASHBOARD_AUTH"))
	}
	if authStr == "" {
		u := strings.TrimSpace(os.Getenv("RW_DASHBOARD_USER"))
		p := strings.TrimSpace(os.Getenv("RW_DASHBOARD_PASS"))
		if p == "" {
			p = strings.TrimSpace(os.Getenv("RW_DASHBOARD_PASSWORD"))
		}
		if u != "" {
			authStr = u + ":" + p
		}
	}
	if hostStr == "" {
		hostStr = strings.TrimSpace(os.Getenv("RW_DASHBOARD_HOST"))
	}

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

	// Initialize embedded SQLite persistence for long-term telemetry retention
	dbPath := filepath.Join(dir, "events.db")
	if sqStore, err := NewSQLiteStore(dbPath); err == nil {
		globalStore.AttachSQLite(sqStore)
		_, _ = sqStore.PruneOlderThan(30) // 30-day retention
		defer sqStore.Close()
	} else {
		fmt.Fprintf(os.Stderr, "⚠️  Warning: SQLite persistence failed to initialize: %v\n", err)
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

	// Continuously stream new logs from discovered containers or monitored file
	if file == "" {
		go watchAndStreamContainers(dashboardCtx, label, container, targets, logFile)
	} else {
		go watchAndStreamFile(dashboardCtx, file, logFile)
	}

	// Server keypair for decryption
	serverPriv, serverPub, err := EnsureServerKeypair(dir)
	if err != nil {
		return fmt.Errorf("initialize server keypair: %w", err)
	}
	serverPubStr := crypto.EncodePublicKey(serverPub)

	mux := NewDashboardHandlerWithAuth(dir, serverPriv, serverPubStr, logFile, nil, "", authStr)

	listenAddr := fmt.Sprintf(":%d", port)
	if hostStr != "" {
		listenAddr = fmt.Sprintf("%s:%d", hostStr, port)
	}

	server := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	go func() {
		<-dashboardCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	dashboardHost := "localhost"
	if hostStr != "" && hostStr != "0.0.0.0" && hostStr != "::" {
		dashboardHost = hostStr
	}
	dashboardURL := fmt.Sprintf("http://%s:%d", dashboardHost, port)
	fmt.Println("🚀 RouteWarden Native SOC Security Dashboard is running!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("📊 Live Dashboard:     %s\n", dashboardURL)
	if authStr != "" {
		parts := strings.SplitN(authStr, ":", 2)
		fmt.Printf("🔒 Authentication:    Enabled (Basic Auth for user '%s')\n", parts[0])
		fmt.Println("🔒 Protected APIs:     /, /api/logs, /api/stream, /api/stats, /api/sources, /api/ip-lookup")
	} else {
		fmt.Println("🔓 Authentication:    None (Open - use --auth <user:pass> to protect)")
	}
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
	if sq := globalStore.SQLite(); sq != nil {
		fmt.Printf("💾 SQLite Persistence: %s (persisted: %d events)\n", sq.DBPath(), sq.Count())
	}
	if IsMaxMindLoaded() {
		fmt.Printf("🌍 MaxMind Database:   %s\n", MaxMindDBPath())
	} else {
		fmt.Printf("🌍 Country Detection:  Auto (Built-in CIDR & RIR DB + MaxMind discovery)\n")
	}
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
				scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
				for scanner.Scan() {
					text := scanner.Text()
					combined := toCombinedLog(text)
					if combined != "" {
						dashboardLogMu.Lock()
						if out != nil {
							_, _ = out.WriteString(combined + "\n")
							_ = out.Sync()
						}
						dashboardLogMu.Unlock()
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
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		text := scanner.Text()
		line := toCombinedLog(text)
		if line != "" {
			dashboardLogMu.Lock()
			if out != nil {
				_, _ = out.WriteString(line + "\n")
			}
			dashboardLogMu.Unlock()
			globalStore.ParseAndIngest(text, "file")
		}
	}
	if err := scanner.Err(); err != nil {
		_ = err
	}
	dashboardLogMu.Lock()
	if out != nil {
		_ = out.Sync()
	}
	dashboardLogMu.Unlock()
}

func watchAndStreamFile(ctx context.Context, filePath string, out *os.File) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	// Seek to end of file to stream only new incoming events
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		offset = 0
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				combined := toCombinedLog(line)
				if combined != "" {
					dashboardLogMu.Lock()
					if out != nil {
						_, _ = out.WriteString(combined + "\n")
						_ = out.Sync()
					}
					dashboardLogMu.Unlock()
					globalStore.ParseAndIngest(line, "file")
				}
			}
			newOffset, _ := f.Seek(0, io.SeekCurrent)
			if newOffset > 0 {
				offset = newOffset
			}
			continue
		}

		if err == io.EOF {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			fi, statErr := os.Stat(filePath)
			if statErr != nil {
				continue
			}

			// Handle truncation (file truncated smaller than current offset)
			if fi.Size() < offset {
				_, _ = f.Seek(0, io.SeekStart)
				offset = 0
				reader.Reset(f)
				continue
			}

			// Handle file rotation (different inode/identity)
			curFi, _ := f.Stat()
			if curFi != nil && !os.SameFile(fi, curFi) {
				newFile, openErr := os.Open(filePath)
				if openErr == nil {
					_ = f.Close()
					f = newFile
					offset = 0
					reader.Reset(f)
				}
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
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

// NewDashboardHandler constructs the HTTP handler for the dashboard and API endpoints.
func NewDashboardHandler(dir string, serverPriv *ecdh.PrivateKey, serverPubStr string, logFile *os.File, wsProxy http.Handler, reportPath string) http.Handler {
	return NewDashboardHandlerWithAuth(dir, serverPriv, serverPubStr, logFile, wsProxy, reportPath, "")
}

// NewDashboardHandlerWithAuth constructs the HTTP handler for the dashboard and API endpoints with optional Basic Auth.
func NewDashboardHandlerWithAuth(dir string, serverPriv *ecdh.PrivateKey, serverPubStr string, logFile *os.File, wsProxy http.Handler, reportPath string, authStr string) http.Handler {

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
		if authStr != "" {
			stats.AuthEnabled = true
			parts := strings.SplitN(authStr, ":", 2)
			stats.AuthUser = parts[0]
		}
		_ = json.NewEncoder(w).Encode(stats)
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

		limit := 50
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
				limit = l
			}
		}

		offset := 0
		if oStr := r.URL.Query().Get("offset"); oStr != "" {
			if o, err := strconv.Atoi(oStr); err == nil && o >= 0 {
				offset = o
			}
		}

		timeParam := strings.TrimSpace(r.URL.Query().Get("time"))
		startTime := strings.TrimSpace(r.URL.Query().Get("start"))
		endTime := strings.TrimSpace(r.URL.Query().Get("end"))
		if startTime == "" && timeParam != "" && timeParam != "ALL" {
			var dur time.Duration
			switch timeParam {
			case "1m":
				dur = 1 * time.Minute
			case "5m":
				dur = 5 * time.Minute
			case "15m":
				dur = 15 * time.Minute
			case "30m":
				dur = 30 * time.Minute
			case "1h":
				dur = 1 * time.Hour
			case "6h":
				dur = 6 * time.Hour
			case "24h":
				dur = 24 * time.Hour
			}
			if dur > 0 {
				startTime = time.Now().Add(-dur).UTC().Format(time.RFC3339)
			}
		}

		nodeParam := strings.TrimSpace(r.URL.Query().Get("node"))
		if nodeParam == "" {
			nodeParam = strings.TrimSpace(r.URL.Query().Get("source"))
		}

		filter := LogQueryFilter{
			StartTime: startTime,
			EndTime:   endTime,
			Verdict:   strings.TrimSpace(r.URL.Query().Get("verdict")),
			ClientIP:  strings.TrimSpace(r.URL.Query().Get("ip")),
			Country:   strings.TrimSpace(r.URL.Query().Get("country")),
			Method:    strings.TrimSpace(r.URL.Query().Get("method")),
			Path:      strings.TrimSpace(r.URL.Query().Get("path")),
			Source:    nodeParam,
			Rule:      strings.TrimSpace(r.URL.Query().Get("rule")),
			Search:    strings.TrimSpace(r.URL.Query().Get("search")),
			StatusStr: strings.TrimSpace(r.URL.Query().Get("status")),
			Limit:     limit,
			Offset:    offset,
		}
		if filter.StatusStr != "" {
			if st, err := strconv.Atoi(filter.StatusStr); err == nil {
				filter.Status = st
			}
		}

		sq := globalStore.SQLite()
		if sq == nil {
			stats := globalStore.GetStats()
			var matched []*SecurityEvent
			for _, ev := range stats.RecentEvents {
				if filter.Verdict != "" && filter.Verdict != "ALL" && !strings.EqualFold(ev.Verdict, filter.Verdict) {
					continue
				}
				if filter.ClientIP != "" && ev.ClientIP != filter.ClientIP {
					continue
				}
				if filter.Country != "" && filter.Country != "ALL" && !strings.EqualFold(ev.Country, filter.Country) && !strings.EqualFold(ev.CountryCode, filter.Country) {
					continue
				}
				if filter.Method != "" && filter.Method != "ALL" && !strings.EqualFold(ev.Method, filter.Method) {
					continue
				}
				if filter.Path != "" && ev.Path != filter.Path {
					continue
				}
				if filter.Source != "" && filter.Source != "ALL" && !strings.EqualFold(ev.Source, filter.Source) {
					continue
				}
				if filter.Rule != "" && filter.Rule != "ALL" && !strings.EqualFold(ev.Rule, filter.Rule) {
					continue
				}
				if filter.StatusStr != "" && filter.StatusStr != "ALL" {
					switch strings.ToLower(filter.StatusStr) {
					case "2xx":
						if ev.Status < 200 || ev.Status >= 300 {
							continue
						}
					case "4xx":
						if ev.Status < 400 || ev.Status >= 500 {
							continue
						}
					case "5xx":
						if ev.Status < 500 || ev.Status >= 600 {
							continue
						}
					default:
						if filter.Status > 0 && ev.Status != filter.Status {
							continue
						}
					}
				}
				if filter.Search != "" {
					searchLower := strings.ToLower(filter.Search)
					haystack := strings.ToLower(ev.ClientIP + " " + ev.Path + " " + ev.Rule + " " + ev.Country + " " + ev.Source)
					if !strings.Contains(haystack, searchLower) {
						continue
					}
				}
				matched = append(matched, ev)
			}
			filteredTotal := len(matched)
			startIdx := offset
			if startIdx > filteredTotal {
				startIdx = filteredTotal
			}
			endIdx := startIdx + limit
			if endIdx > filteredTotal {
				endIdx = filteredTotal
			}
			paged := matched[startIdx:endIdx]
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"events":         paged,
				"total":          len(stats.RecentEvents),
				"filtered_total": filteredTotal,
				"count":          len(paged),
				"limit":          limit,
				"offset":         offset,
			})
			return
		}

		events, err := sq.Query(filter)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"events":         events,
			"total":          sq.Count(),
			"filtered_total": sq.CountFiltered(filter),
			"count":          len(events),
			"limit":          limit,
			"offset":         offset,
		})
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

	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(FaviconICO)
	})

	mux.HandleFunc("/icon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(FaviconSVG)
	})

	mux.HandleFunc("/api/v1/pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"public_key": serverPubStr,
			"version":    Version,
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
		dashboardLogMu.Lock()
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
		dashboardLogMu.Unlock()

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

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(CustomAuthScreenHTML))
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "routewarden_auth",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "routewarden_auth",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	})

	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request format"})
			return
		}

		if authStr == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "user": creds.Username})
			return
		}

		var userMatch, passMatch bool
		expUser := authStr
		if strings.Contains(authStr, ":") {
			parts := strings.SplitN(authStr, ":", 2)
			expUser = parts[0]
			expPass := parts[1]
			userMatch = subtle.ConstantTimeCompare([]byte(creds.Username), []byte(expUser)) == 1
			passMatch = subtle.ConstantTimeCompare([]byte(creds.Password), []byte(expPass)) == 1
		} else {
			// Single token auth: user can supply the token in username or password field
			userMatch = subtle.ConstantTimeCompare([]byte(creds.Username), []byte(authStr)) == 1 ||
				subtle.ConstantTimeCompare([]byte(creds.Password), []byte(authStr)) == 1
			passMatch = true
		}

		if !userMatch || !passMatch {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid username or access key"})
			return
		}

		token := base64.StdEncoding.EncodeToString([]byte(authStr))
		http.SetCookie(w, &http.Cookie{
			Name:     "routewarden_auth",
			Value:    token,
			Path:     "/",
			MaxAge:   86400 * 30, // 30 days
			SameSite: http.SameSiteLaxMode,
			HttpOnly: false,
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"user":   expUser,
			"token":  token,
		})
	})

	if authStr == "" {
		return mux
	}

	parts := strings.SplitN(authStr, ":", 2)
	expectedUser := parts[0]
	expectedPass := ""
	if len(parts) > 1 {
		expectedPass = parts[1]
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Whitelist static branding, agent ingestion APIs, and auth endpoints
		if path == "/favicon.ico" || path == "/icon.svg" ||
			strings.HasPrefix(path, "/api/v1/") ||
			path == "/api/auth/login" || path == "/api/auth/logout" ||
			path == "/logout" {
			mux.ServeHTTP(w, r)
			return
		}

		isAuthed := validateDashboardAuth(r, expectedUser, expectedPass, authStr)

		// Handle /login route
		if path == "/login" {
			if isAuthed {
				dest := r.URL.Query().Get("redirect")
				if dest == "" {
					dest = "/"
				}
				http.Redirect(w, r, dest, http.StatusFound)
				return
			}
			mux.ServeHTTP(w, r)
			return
		}

		if isAuthed {
			mux.ServeHTTP(w, r)
			return
		}

		// Unauthenticated handling:
		// If it's a browser requesting HTML at / or /index.html, redirect to /login
		isBrowserHTML := strings.Contains(r.Header.Get("Accept"), "text/html")
		if isBrowserHTML && (path == "/" || path == "/index.html") {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Unauthorized response for API / curl / test clients
		w.Header().Set("WWW-Authenticate", `Basic realm="RouteWarden SOC Security Dashboard"`)
		if strings.HasPrefix(path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized: valid dashboard credentials required",
			})
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized: RouteWarden SOC Dashboard requires authentication\n"))
	})
}

// validateDashboardAuth verifies request credentials via Basic Auth, cookie, query token, or Bearer header.
func validateDashboardAuth(r *http.Request, expectedUser, expectedPass, authStr string) bool {
	hasColon := strings.Contains(authStr, ":")

	// 1. Check HTTP Basic Auth header
	u, p, ok := r.BasicAuth()
	if ok {
		if hasColon {
			if subtle.ConstantTimeCompare([]byte(u), []byte(expectedUser)) == 1 &&
				subtle.ConstantTimeCompare([]byte(p), []byte(expectedPass)) == 1 {
				return true
			}
		} else {
			if subtle.ConstantTimeCompare([]byte(u), []byte(authStr)) == 1 ||
				subtle.ConstantTimeCompare([]byte(p), []byte(authStr)) == 1 {
				return true
			}
		}
	}

	// 2. Check Cookie (routewarden_auth or rw_auth)
	for _, cookieName := range []string{"routewarden_auth", "rw_auth"} {
		if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
			if raw, err := base64.StdEncoding.DecodeString(c.Value); err == nil {
				parts := strings.SplitN(string(raw), ":", 2)
				u := parts[0]
				p := ""
				if len(parts) > 1 {
					p = parts[1]
				}
				if hasColon {
					if subtle.ConstantTimeCompare([]byte(u), []byte(expectedUser)) == 1 &&
						subtle.ConstantTimeCompare([]byte(p), []byte(expectedPass)) == 1 {
						return true
					}
				} else {
					if subtle.ConstantTimeCompare([]byte(u), []byte(authStr)) == 1 ||
						subtle.ConstantTimeCompare([]byte(p), []byte(authStr)) == 1 {
						return true
					}
				}
			} else if subtle.ConstantTimeCompare([]byte(c.Value), []byte(authStr)) == 1 ||
				(expectedPass != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(expectedPass)) == 1) {
				return true
			}
		}
	}

	// 3. Check query parameter ?auth=user:pass or ?token=pass
	qAuth := r.URL.Query().Get("auth")
	if qAuth == "" {
		qAuth = r.URL.Query().Get("token")
	}
	if qAuth != "" {
		if subtle.ConstantTimeCompare([]byte(qAuth), []byte(authStr)) == 1 ||
			(expectedPass != "" && subtle.ConstantTimeCompare([]byte(qAuth), []byte(expectedPass)) == 1) {
			return true
		}
	}

	// 4. Check Bearer token header
	bearer := extractAuthToken(r)
	if bearer != "" {
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(authStr)) == 1 ||
			(expectedPass != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(expectedPass)) == 1) {
			return true
		}
	}

	return false
}
