package observability

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
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

type SourceInfo struct {
	Mode    string            `json:"mode"`
	File    string            `json:"file,omitempty"`
	Targets []containerTarget `json:"targets,omitempty"`
}

var (
	sourceMu   sync.RWMutex
	currSource SourceInfo
)

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
	return currSource
}

const sourceBadgeInjection = `
<style>
#rw-status-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  background: rgba(22, 25, 34, 0.85);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 8px;
  padding: 8px 14px;
  margin: 12px 0 16px 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 13px;
  color: #e2e8f0;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
  transition: all 0.2s ease-in-out;
}
.rw-pulse {
  width: 8px;
  height: 8px;
  background-color: #10b981;
  border-radius: 50%;
  display: inline-block;
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
  animation: rw-pulse-anim 2s infinite;
}
@keyframes rw-pulse-anim {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
  70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}
.rw-pulse-idle {
  width: 8px;
  height: 8px;
  background-color: #f59e0b;
  border-radius: 50%;
  display: inline-block;
}
.rw-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(255, 255, 255, 0.08);
  border: 1px solid rgba(255, 255, 255, 0.15);
  border-radius: 4px;
  padding: 3px 9px;
  font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  color: #93c5fd;
}
.rw-tag-id {
  color: #94a3b8;
  font-size: 11px;
}
.rw-label {
  font-weight: 600;
  color: #cbd5e1;
  display: flex;
  align-items: center;
  gap: 7px;
}
</style>
<script>
(function() {
  function createOrUpdateBar(data) {
    var bar = document.getElementById('rw-status-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'rw-status-bar';
      var titleElem = document.getElementById('report-title');
      if (titleElem && titleElem.parentNode) {
        titleElem.parentNode.insertBefore(bar, titleElem.nextSibling);
      } else {
        var container = document.querySelector('.container') || document.body;
        container.insertBefore(bar, container.firstChild);
      }
    }

    var content = '';
    if (data.mode === 'file') {
      content += '<div class="rw-label"><span class="rw-pulse"></span> Monitored Source:</div>';
      content += '<span class="rw-tag">📁 ' + (data.file || 'Local Log File') + '</span>';
    } else if (data.targets && data.targets.length > 0) {
      content += '<div class="rw-label"><span class="rw-pulse"></span> Monitored Containers:</div>';
      data.targets.forEach(function(t) {
        var shortID = (t.id && t.id.length > 12) ? t.id.substring(0, 12) : t.id;
        content += '<span class="rw-tag">🐳 ' + t.name + ' <span class="rw-tag-id">(' + shortID + ')</span></span>';
      });
      content += '<span style="color:#64748b; font-size:11px; margin-left:auto;">' + data.targets.length + ' active container' + (data.targets.length > 1 ? 's' : '') + '</span>';
    } else {
      content += '<div class="rw-label"><span class="rw-pulse-idle"></span> Auto-Discovery:</div>';
      content += '<span style="color:#94a3b8; font-style:italic; font-size:12px;">Waiting for gateway containers with label <code>routewarden=true</code>...</span>';
    }
    bar.innerHTML = content;
  }

  function fetchSources() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/sources', true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          createOrUpdateBar(data);
        } catch(e) {}
      }
    };
    xhr.send();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fetchSources);
  } else {
    fetchSources();
  }
  setInterval(fetchSources, 3000);
})();
</script>
`

type streamMsg struct {
	Container string
	Line      string
}

type logEvent struct {
	Timestamp      string  `json:"time"`
	TimestampAlt   string  `json:"timestamp"`
	ClientIP       string  `json:"client_ip"`
	ClientIPAlt    string  `json:"ip"`
	Verdict        string  `json:"verdict"`
	Method         string  `json:"method"`
	Path           string  `json:"path"`
	PathAlt        string  `json:"request_uri"`
	MatchedPattern string  `json:"matched_pattern"`
	MatchedRuleAlt string  `json:"rule"`
	StatusCode     int     `json:"status"`
	StatusCodeAlt  int     `json:"status_code"`
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
	if combinedLogRegex.MatchString(line) {
		return line
	}

	// Try JSON format
	var ev logEvent
	if err := json.Unmarshal([]byte(line), &ev); err == nil && (ev.Path != "" || ev.PathAlt != "" || ev.ClientIP != "" || ev.ClientIPAlt != "" || ev.Verdict != "") {
		ip := ev.ClientIP
		if ip == "" {
			ip = ev.ClientIPAlt
		}
		if ip == "" {
			ip = "127.0.0.1"
		}

		path := ev.Path
		if path == "" {
			path = ev.PathAlt
		}
		if path == "" {
			path = "/"
		}
		path = strings.ReplaceAll(path, `"`, "%22")

		method := ev.Method
		if method == "" {
			method = "GET"
		}
		method = strings.ReplaceAll(method, `"`, "")

		status := ev.StatusCode
		if status == 0 {
			status = ev.StatusCodeAlt
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
		if rule == "" {
			rule = "RouteWarden"
		}
		rule = strings.ReplaceAll(rule, `"`, `'`)

		return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d 0 \"-\" \"%s\"", ip, timeStr, method, path, status, rule)
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

	reportPath := filepath.Join(dir, "index.html")
	logFilePath := filepath.Join(dir, "access.log")
	confPath := filepath.Join(dir, "goaccess.conf")

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

	// Prime access.log with initial logs from targets so GoAccess renders immediately
	if len(targets) > 0 {
		for _, target := range targets {
			cmd := exec.Command("docker", "logs", "--tail", "100", target.ID)
			if out, err := cmd.CombinedOutput(); err == nil {
				for _, l := range strings.Split(string(out), "\n") {
					combined := toCombinedLog(l)
					if combined != "" {
						_, _ = logFile.WriteString(combined + "\n")
					}
				}
				_ = logFile.Sync()
			}
		}
	} else if file == "" {
		initLine := toCombinedLog(`{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","client_ip":"127.0.0.1","method":"GET","path":"/health","verdict":"ALLOW"}`)
		_, _ = logFile.WriteString(initLine + "\n")
		_ = logFile.Sync()
	}

	wsPort, err := getFreePort()
	if err != nil {
		wsPort = port + 1
	}

	goaccessBin, errGoaccess := FindGoAccess()
	dockerBin, errDocker := FindDocker()

	if errGoaccess != nil && errDocker != nil {
		return fmt.Errorf("neither 'goaccess' nor 'docker' is installed. Please install GoAccess (brew install goaccess / apt install goaccess) or Docker")
	}

	useDockerGoaccess := (errGoaccess != nil)
	var goaccessCmd *exec.Cmd

	if !useDockerGoaccess {
		// Run native GoAccess
		wsURL := fmt.Sprintf("ws://localhost:%d/ws", port)
		args := []string{
			logFilePath,
			"--config-file=" + confPath,
			"--real-time-html",
			fmt.Sprintf("--port=%d", wsPort),
			"--addr=127.0.0.1",
			"--ws-url=" + wsURL,
			"-o", reportPath,
		}
		goaccessCmd = exec.CommandContext(dashboardCtx, goaccessBin, args...)
	} else {
		// Run GoAccess via Docker container (allinurl/goaccess:latest entrypoint is goaccess)
		wsURL := fmt.Sprintf("ws://localhost:%d/ws", port)
		_ = exec.Command("docker", "rm", "-f", "routewarden-dashboard").Run()

		args := []string{
			"run", "--rm",
			"--name", "routewarden-dashboard",
			"-p", fmt.Sprintf("127.0.0.1:%d:7890", wsPort),
			"-v", fmt.Sprintf("%s:/srv/report", dir),
			"allinurl/goaccess:latest",
			"/srv/report/access.log",
			"--config-file=/srv/report/goaccess.conf",
			"--real-time-html",
			"--port=7890",
			"--addr=0.0.0.0",
			"--ws-url=" + wsURL,
			"-o", "/srv/report/index.html",
		}
		goaccessCmd = exec.CommandContext(dashboardCtx, dockerBin, args...)
	}

	if err := goaccessCmd.Start(); err != nil {
		return fmt.Errorf("start GoAccess engine: %w", err)
	}

	// Monitor GoAccess exit
	go func() {
		if err := goaccessCmd.Wait(); err != nil && dashboardCtx.Err() == nil {
			fmt.Fprintf(os.Stderr, "GoAccess process exited: %v\n", err)
		}
	}()

	defer func() {
		if goaccessCmd.Process != nil {
			_ = goaccessCmd.Process.Kill()
		}
		if useDockerGoaccess {
			_ = exec.Command("docker", "rm", "-f", "routewarden-dashboard").Run()
		}
	}()

	// Continuously stream new logs from discovered containers and watch lifecycle
	if file == "" {
		go watchAndStreamContainers(dashboardCtx, label, container, targets, logFile)
	}

	// Setup ReverseProxy for WebSocket and HTTP Server
	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", wsPort))
	wsProxy := httputil.NewSingleHostReverseProxy(targetURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/sources", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		_ = json.NewEncoder(w).Encode(getSourceInfo())
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" || strings.HasPrefix(r.URL.Path, "/ws") {
			wsProxy.ServeHTTP(w, r)
			return
		}

		if _, err := os.Stat(reportPath); err == nil {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			htmlBytes, err := os.ReadFile(reportPath)
			if err != nil {
				http.ServeFile(w, r, reportPath)
				return
			}
			injected := bytes.Replace(htmlBytes, []byte("</body>"), []byte(sourceBadgeInjection+"</body>"), 1)
			_, _ = w.Write(injected)
			return
		}

		// Initial splash screen while report is being generated
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="1"><title>RouteWarden Dashboard</title></head><body style="background:#1a1d21;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;margin:0;"><h2 style="margin:0 0 10px 0;">🚀 RouteWarden Security Dashboard</h2><p style="color:#9ba1a6;">Initializing real-time GoAccess stream...</p></body></html>`))
	})

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
	fmt.Println("🚀 RouteWarden Security Dashboard (GoAccess) is running!")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("📊 Live Dashboard:     %s\n", dashboardURL)
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
	fmt.Printf("⚡ Memory Footprint:   ~15MB\n")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("Press Ctrl+C to stop.")

	if !noOpen {
		go func() {
			time.Sleep(800 * time.Millisecond)
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
					combined := toCombinedLog(scanner.Text())
					if combined != "" {
						mu.Lock()
						_, _ = out.WriteString(combined + "\n")
						_ = out.Sync()
						mu.Unlock()
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
		line := toCombinedLog(scanner.Text())
		if line != "" {
			_, _ = out.WriteString(line + "\n")
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
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
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
