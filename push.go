package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/routewarden/cli/crypto"
)

type pushPayload struct {
	AgentID  string   `json:"agent_id"`
	Hostname string   `json:"hostname"`
	Events   []string `json:"events"`
}

func handlePush(args []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch strings.ToLower(args[0]) {
		case "status", "ps":
			checkDaemonStatus("push", "RouteWarden Remote Shipper")
			return
		case "stop", "down":
			_, _ = stopDaemon("push", "RouteWarden Remote Shipper")
			return
		}
	}

	fs := flag.NewFlagSet("push", flag.ExitOnError)
	urlFlag := fs.String("url", "", "RouteWarden dashboard URL (overrides registered config)")
	fs.StringVar(urlFlag, "u", "", "Alias for --url")
	keyFlag := fs.String("key", "", "Remote agent authentication key (overrides registered config)")
	fs.StringVar(keyFlag, "k", "", "Alias for --key")
	configPath := fs.String("config", "", "Custom path to agent configuration (default: ~/.routewarden/agent.json)")
	dockerMode := fs.Bool("docker", false, "Auto-discover and tail Docker containers with label 'routewarden=true'")
	detachMode := fs.Bool("detach", false, "Run remote shipper in background (detached) mode")
	fs.BoolVar(detachMode, "d", false, "Alias for --detach")
	var containerFlags stringSlice
	fs.Var(&containerFlags, "container", "Tail specific Docker container(s) by name or ID (repeatable or comma-separated)")
	fs.Var(&containerFlags, "c", "Alias for --container")
	var fileFlags stringSlice
	fs.Var(&fileFlags, "file", "Log file(s) to monitor and push (repeatable, comma-separated, or glob pattern)")
	fs.Var(&fileFlags, "f", "Alias for --file")
	var eventFlags stringSlice
	fs.Var(&eventFlags, "event", "Push one or more specific event strings directly (repeatable)")
	fs.Var(&eventFlags, "e", "Alias for --event")
	stdinMode := fs.Bool("stdin", false, "Read and push events line-by-line from STDIN")
	customLabel := fs.String("label", "", "Docker label to filter containers (default: routewarden=true)")
	fs.StringVar(customLabel, "l", "", "Alias for --label")
	tailLines := fs.String("tail", "50", "Initial lines to tail from Docker container(s) and log file(s)")
	batchSize := fs.Int("batch-size", 50, "Maximum events to buffer before flushing")
	flushInterval := fs.Duration("flush-interval", 1*time.Second, "Maximum duration to buffer events before flushing")
	verbose := fs.Bool("verbose", false, "Enable verbose event-level logging")
	fs.BoolVar(verbose, "v", false, "Alias for --verbose")
	allLogs := fs.Bool("all-logs", false, "Ship all container lines without filtering for RouteWarden logs")
	_ = parseFlagsLenient(fs, args)

	filesToMonitor := resolveFileList(fileFlags, fs.Args())
	containersToTail := resolveContainerList(containerFlags)

	hasStdin := *stdinMode
	var diskFiles []string
	for _, f := range filesToMonitor {
		if f == "-" {
			hasStdin = true
		} else {
			diskFiles = append(diskFiles, f)
		}
	}
	filesToMonitor = diskFiles

	isManualPush := len(eventFlags) > 0 || hasStdin

	if *detachMode && !isManualPush && os.Getenv("_RW_DETACHED") != "1" {
		_ = spawnDetached("push", "RouteWarden Remote Shipper", append([]string{"push"}, args...), 0, "")
		return
	}

	if os.Getenv("_RW_DETACHED") == "1" {
		defer removePID("push")
	}

	runDockerDiscovery := !isManualPush && (*dockerMode || (len(filesToMonitor) == 0 && len(containersToTail) == 0))

	if *urlFlag == "" {
		if envURL := os.Getenv("RW_DASHBOARD_URL"); envURL != "" {
			*urlFlag = envURL
		} else if envURL := os.Getenv("RW_URL"); envURL != "" {
			*urlFlag = envURL
		}
	}
	if *keyFlag == "" {
		if envKey := os.Getenv("RW_AGENT_KEY"); envKey != "" {
			*keyFlag = envKey
		} else if envKey := os.Getenv("RW_KEY"); envKey != "" {
			*keyFlag = envKey
		}
	}

	// Load configuration
	agentCfg, err := loadAgentConfig(*configPath)
	if err != nil && (*urlFlag == "" || *keyFlag == "") {
		fmt.Fprintln(os.Stderr, "❌ RouteWarden is not registered on this node, and --url / --key were not provided.")
		fmt.Fprintln(os.Stderr, "\nTo register this server, run:")
		fmt.Fprintln(os.Stderr, "  rwarden register --url http://<dashboard-ip>:7890 --key <agent-token>")
		fmt.Fprintln(os.Stderr, "\nOr push directly with flags (or RW_DASHBOARD_URL and RW_AGENT_KEY):")
		fmt.Fprintln(os.Stderr, "  rwarden push --url http://<dashboard-ip>:7890 --key <agent-token> --docker")
		os.Exit(1)
	}

	dashboardURL := ""
	agentToken := ""
	agentID := ""
	agentName := ""
	serverPubKeyStr := ""

	if agentCfg != nil {
		dashboardURL = agentCfg.DashboardURL
		agentToken = agentCfg.AgentToken
		agentID = agentCfg.AgentID
		agentName = agentCfg.AgentName
		serverPubKeyStr = agentCfg.ServerPublicKey
	}

	if *urlFlag != "" {
		dashboardURL = strings.TrimRight(*urlFlag, "/")
	}
	if *keyFlag != "" {
		agentToken = *keyFlag
	}

	hostname, _ := os.Hostname()
	if agentName == "" {
		agentName = hostname
	}
	if agentID == "" {
		agentID = hostname
	}

	// Parse server public key if present
	var serverPubKey *ecdh.PublicKey
	if serverPubKeyStr != "" {
		if pk, err := crypto.DecodePublicKey(serverPubKeyStr); err == nil {
			serverPubKey = pk
		}
	} else if dashboardURL != "" {
		if pk := fetchServerPubKey(dashboardURL); pk != nil {
			serverPubKey = pk
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// ─── 1. Manual Direct Push via --event / -e ───────────────────────────────
	if len(eventFlags) > 0 {
		var eventsToPush []string
		for _, ev := range eventFlags {
			ev = strings.TrimSpace(ev)
			if ev != "" {
				eventsToPush = append(eventsToPush, ev)
			}
		}
		if len(eventsToPush) == 0 {
			fmt.Fprintln(os.Stderr, "❌ Error: --event specified but no non-empty event strings provided.")
			os.Exit(1)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		eventsURL := dashboardURL + "/api/v1/events"
		ts := time.Now().Format("15:04:05")
		if err := sendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, eventsToPush); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] ❌ Failed to push event(s): %v\n", ts, err)
			os.Exit(1)
		}
		fmt.Printf("[%s] 📦 Pushed batch of %d event(s) to dashboard (total: %d)\n", ts, len(eventsToPush), len(eventsToPush))
		if *verbose {
			for _, ev := range eventsToPush {
				fmt.Printf("[%s]    ↳ %s\n", ts, ev)
			}
		}
		fmt.Printf("✅ Successfully pushed %d event(s) to RouteWarden dashboard\n", len(eventsToPush))
		return
	}

	// ─── 2. Manual Piped Push via STDIN (--stdin or -f -) ─────────────────────
	if hasStdin {
		client := &http.Client{Timeout: 10 * time.Second}
		eventsURL := dashboardURL + "/api/v1/events"

		stdinChan := make(chan string, 1000)
		scannerErrChan := make(chan error, 1)

		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					select {
					case stdinChan <- line:
					case <-ctx.Done():
						return
					}
				}
			}
			if err := scanner.Err(); err != nil {
				scannerErrChan <- err
			}
			close(stdinChan)
		}()

		var buffer []string
		totalPushed := 0
		ticker := time.NewTicker(*flushInterval)
		defer ticker.Stop()

		flush := func() error {
			if len(buffer) == 0 {
				return nil
			}
			batch := buffer
			buffer = nil
			ts := time.Now().Format("15:04:05")
			if err := sendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, batch); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] ❌ Failed to push event batch: %v\n", ts, err)
				return err
			}
			totalPushed += len(batch)
			fmt.Printf("[%s] 📦 Pushed batch of %d event(s) to dashboard (total: %d)\n", ts, len(batch), totalPushed)
			if *verbose {
				for _, ev := range batch {
					fmt.Printf("[%s]    ↳ %s\n", ts, ev)
				}
			}
			return nil
		}

		done := false
		for !done {
			select {
			case <-ctx.Done():
				_ = flush()
				fmt.Printf("[%s] ✅ STDIN stream interrupted. Total events pushed: %d\n", time.Now().Format("15:04:05"), totalPushed)
				return

			case line, ok := <-stdinChan:
				if !ok {
					done = true
					break
				}
				buffer = append(buffer, line)
				if len(buffer) >= *batchSize {
					if err := flush(); err != nil {
						os.Exit(1)
					}
				}

			case <-ticker.C:
				if err := flush(); err != nil {
					os.Exit(1)
				}
			}
		}

		select {
		case err := <-scannerErrChan:
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error reading from STDIN: %v\n", err)
				os.Exit(1)
			}
		default:
		}

		if err := flush(); err != nil {
			os.Exit(1)
		}

		fmt.Printf("✅ Successfully pushed %d event(s) from STDIN to RouteWarden dashboard\n", totalPushed)
		return
	}

	fmt.Println("🚀 RouteWarden Remote Shipper Starting...")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("  Dashboard URL:   %s\n", dashboardURL)
	fmt.Printf("  Agent Name:      %s\n", agentName)
	if serverPubKey != nil {
		fmt.Println("  Encryption:      🔒 End-to-End Encrypted (X25519 + AES-256-GCM)")
	} else {
		fmt.Println("  Encryption:      Standard HTTPS/HTTP")
	}
	fmt.Printf("  Batch Settings:  Size=%d, Interval=%s\n", *batchSize, *flushInterval)
	if *allLogs {
		fmt.Println("  Filter:          Disabled (--all-logs: shipping all raw lines)")
	} else {
		fmt.Println("  Filter:          RouteWarden logs only (security events & access logs)")
	}
	if *verbose {
		fmt.Println("  Logging:         Verbose enabled (event-level previews)")
	} else {
		fmt.Println("  Logging:         Active (batch-level confirmation)")
	}

	// Setup ring buffer
	const maxRingBuffer = 2000
	eventChan := make(chan string, maxRingBuffer)

	// Start collector(s)
	if len(filesToMonitor) > 0 {
		for _, f := range filesToMonitor {
			fmt.Printf("  Monitoring File: %s\n", f)
			go tailFileToChan(ctx, f, *tailLines, eventChan)
		}
	}
	if len(containersToTail) > 0 {
		for _, c := range containersToTail {
			fmt.Printf("  Container:       %s\n", c)
			go tailContainerToChan(ctx, c, *tailLines, *allLogs, eventChan)
		}
	}
	if runDockerDiscovery {
		labelDesc := "'routewarden=true'"
		if *customLabel != "" {
			labelDesc = fmt.Sprintf("'%s'", *customLabel)
		}
		fmt.Printf("  Auto-Discovery:  Watching Docker containers with label %s\n", labelDesc)
		go watchDockerContainersToChan(ctx, *customLabel, *tailLines, *allLogs, eventChan)
	}

	// Dynamic observer: continuously watch for new log files matching glob patterns or directories
	var hasGlobOrDir bool
	for _, flagVal := range append(append([]string{}, fileFlags...), fs.Args()...) {
		for part := range strings.SplitSeq(flagVal, ",") {
			part = strings.TrimSpace(part)
			if strings.ContainsAny(part, "*?[]") {
				hasGlobOrDir = true
				break
			}
			if fi, err := os.Stat(part); err == nil && fi.IsDir() {
				hasGlobOrDir = true
				break
			}
		}
	}
	if hasGlobOrDir {
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			monitored := make(map[string]bool)
			for _, f := range filesToMonitor {
				monitored[f] = true
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current := resolveFileList(fileFlags, fs.Args())
					for _, f := range current {
						if f == "-" {
							continue
						}
						if !monitored[f] {
							monitored[f] = true
							fmt.Printf("📄 [File] Attached to new log file: %s\n", f)
							go tailFileToChan(ctx, f, *tailLines, eventChan)
						}
					}
				}
			}
		}()
	}
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("Press Ctrl+C to stop.")

	// Start Heartbeat routine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		client := &http.Client{Timeout: 5 * time.Second}
		hbURL := dashboardURL + "/api/v1/heartbeat"

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				payload, _ := json.Marshal(map[string]string{"hostname": hostname})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, hbURL, bytes.NewReader(payload))
				if err == nil {
					req.Header.Set("Authorization", "Bearer "+agentToken)
					req.Header.Set("Content-Type", "application/json")
					resp, err := client.Do(req)
					if err == nil {
						_ = resp.Body.Close()
					}
				}
			}
		}
	}()

	// Start Batch Flusher
	client := &http.Client{Timeout: 10 * time.Second}
	eventsURL := dashboardURL + "/api/v1/events"

	var buffer []string
	totalShipped := 0
	ticker := time.NewTicker(*flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(buffer) == 0 {
			return
		}
		batch := buffer
		buffer = nil
		ts := time.Now().Format("15:04:05")
		if err := sendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, batch); err != nil {
			fmt.Fprintf(os.Stderr, "[%s] ❌ Failed to push batch of %d event(s): %v\n", ts, len(batch), err)
			return
		}
		totalShipped += len(batch)
		fmt.Printf("[%s] 📦 Pushed batch of %d event(s) to dashboard (total: %d)\n", ts, len(batch), totalShipped)
		if *verbose {
			for _, ev := range batch {
				fmt.Printf("[%s]    ↳ %s\n", ts, ev)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			fmt.Printf("\n✅ Remote shipper stopped. (Total events pushed: %d)\n", totalShipped)
			return

		case line := <-eventChan:
			buffer = append(buffer, line)
			if len(buffer) >= *batchSize {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func tailFileToChan(ctx context.Context, path, tailLines string, out chan<- string) {
	if tailLines == "" {
		tailLines = "50"
	}
	cmd := exec.CommandContext(ctx, "tail", "-F", "-n", tailLines, path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [File %s] Failed to open pipe: %v; falling back to native file watcher\n", path, err)
		streamFileToChan(ctx, path, tailLines, out)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [File %s] Failed to start tail command: %v; falling back to native file watcher\n", path, err)
		streamFileToChan(ctx, path, tailLines, out)
		return
	}
	defer func() {
		_ = cmd.Wait()
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		case out <- scanner.Text():
		}
	}
	if err := scanner.Err(); err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "⚠️ [File %s] Scanner error: %v; switching to native file watcher\n", path, err)
			streamFileToChan(ctx, path, "0", out)
		}
	}
}

func streamFileToChan(ctx context.Context, path, tailLines string, out chan<- string) {
	var f *os.File
	for {
		var err error
		f, err = os.Open(path)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	nTail := 50
	if tailLines != "" {
		if n, err := strconv.Atoi(tailLines); err == nil && n >= 0 {
			nTail = n
		}
	}

	if nTail > 0 {
		fi, err := f.Stat()
		if err == nil {
			var seekPos int64
			if fi.Size() > 256*1024 {
				seekPos = fi.Size() - 256*1024
			}
			_, _ = f.Seek(seekPos, io.SeekStart)
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
			var initialLines []string
			for scanner.Scan() {
				initialLines = append(initialLines, scanner.Text())
			}
			if scanErr := scanner.Err(); scanErr != nil {
				fmt.Fprintf(os.Stderr, "⚠️ [File %s] Scanner error during initial tail: %v\n", path, scanErr)
			}
			if len(initialLines) > nTail {
				initialLines = initialLines[len(initialLines)-nTail:]
			}
			for _, l := range initialLines {
				select {
				case <-ctx.Done():
					return
				case out <- l:
				}
			}
		}
	}

	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		offset = 0
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var pendingLine string

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err == nil {
			offset += int64(len(line))
			if pendingLine != "" {
				line = pendingLine + line
				pendingLine = ""
			}
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				select {
				case <-ctx.Done():
					return
				case out <- line:
				}
			}
			continue
		}

		if err == io.EOF {
			if len(line) > 0 {
				offset += int64(len(line))
				pendingLine += line
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			fi, statErr := os.Stat(path)
			if statErr != nil {
				continue
			}

			// Handle in-place truncation
			if fi.Size() < offset {
				_, _ = f.Seek(0, io.SeekStart)
				offset = 0
				pendingLine = ""
				reader.Reset(f)
				continue
			}

			// Handle rotation
			curFi, _ := f.Stat()
			if curFi != nil && !os.SameFile(fi, curFi) {
				for {
					extraLine, rErr := reader.ReadString('\n')
					if extraLine != "" {
						combinedStr := pendingLine + extraLine
						pendingLine = ""
						trimmed := strings.TrimRight(combinedStr, "\r\n")
						if trimmed != "" {
							select {
							case <-ctx.Done():
								return
							case out <- trimmed:
							}
						}
					}
					if rErr != nil {
						break
					}
				}

				newFile, openErr := os.Open(path)
				if openErr == nil {
					_ = f.Close()
					f = newFile
					offset = 0
					pendingLine = ""
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

// dockerTimestampPrefixRegex matches Docker's optional leading RFC3339 timestamp:
// e.g. "2026-10-20T14:00:01.123456789Z "
var dockerTimestampPrefixRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\s+`)

type routeWardenCheck struct {
	ClientIP       string `json:"client_ip"`
	ClientIPAlt    string `json:"ip"`
	ClientHost     string `json:"ClientHost"`
	Verdict        string `json:"verdict"`
	Action         string `json:"action"`
	Method         string `json:"method"`
	RequestMethod  string `json:"RequestMethod"`
	Path           string `json:"path"`
	PathAlt        string `json:"request_uri"`
	RequestPath    string `json:"RequestPath"`
	MatchedPattern string `json:"matched_pattern"`
	Rule           string `json:"rule"`
	StatusCode     int    `json:"status"`
	StatusCodeAlt  int    `json:"status_code"`
	DownstreamStat int    `json:"DownstreamStatus"`
	Plugin         string `json:"plugin"`
	Gateway        string `json:"gateway"`
}

// isRouteWardenLog returns true if line is a valid RouteWarden security event or proxy access log.
func isRouteWardenLog(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}

	// 1. Check for standard Combined / Common Access Log format
	if combinedLogRegex.MatchString(line) {
		return true
	}

	// 2. Check for RouteWarden structured JSON log event
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		var ev routeWardenCheck
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			// Security enforcement events (e.g. BLOCK, ALLOW, TARPIT)
			if ev.Verdict != "" || ev.Action != "" {
				return true
			}
			// Threat rule or pattern detection
			if ev.Rule != "" || ev.MatchedPattern != "" {
				return true
			}
			// RouteWarden / TCP Warden plugin tags
			if ev.Plugin != "" || ev.Gateway != "" {
				return true
			}
			// Access events: must have client IP and (request path or HTTP method or status code)
			hasIP := ev.ClientIP != "" || ev.ClientIPAlt != "" || ev.ClientHost != ""
			hasPath := ev.Path != "" || ev.PathAlt != "" || ev.RequestPath != ""
			hasMethod := ev.Method != "" || ev.RequestMethod != ""
			hasStatus := ev.StatusCode > 0 || ev.StatusCodeAlt > 0 || ev.DownstreamStat > 0

			if hasIP && (hasPath || hasMethod || hasStatus) {
				return true
			}
			if hasPath && hasMethod {
				return true
			}
		}
	}

	return false
}

func filterRouteWardenLog(line string, allLogs bool) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	if allLogs {
		return line, true
	}
	cleanLine := line
	if loc := dockerTimestampPrefixRegex.FindStringIndex(line); loc != nil && loc[0] == 0 {
		cleanLine = strings.TrimSpace(line[loc[1]:])
	}
	if isRouteWardenLog(cleanLine) {
		return cleanLine, true
	}
	return "", false
}

func tailContainerToChan(ctx context.Context, containerName, tailLines string, allLogs bool, out chan<- string) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--tail", tailLines, containerName)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [Container %s] Failed to open stdout pipe: %v\n", containerName, err)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [Container %s] Failed to open stderr pipe: %v\n", containerName, err)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [Container %s] Failed to start docker logs: %v\n", containerName, err)
		return
	}

	readPipe := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			rawText := scanner.Text()
			cleanText, ok := filterRouteWardenLog(rawText, allLogs)
			if !ok {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case out <- cleanText:
			}
		}
		if err := scanner.Err(); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "⚠️ [Container %s] Scanner error: %v\n", containerName, err)
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		readPipe(stdout)
	}()
	go func() {
		defer wg.Done()
		readPipe(stderr)
	}()
	wg.Wait()
	_ = cmd.Wait()
}

func watchDockerContainersToChan(ctx context.Context, customLabel, tailLines string, allLogs bool, out chan<- string) {
	var mu sync.Mutex
	active := make(map[string]context.CancelFunc)

	startStream := func(id, name string) {
		mu.Lock()
		if _, exists := active[id]; exists {
			mu.Unlock()
			return
		}
		cCtx, cancel := context.WithCancel(ctx)
		active[id] = cancel
		mu.Unlock()

		fmt.Printf("🐳 [Docker] Attached to container: %s (%s)\n", name, id[:min(12, len(id))])

		go func() {
			defer func() {
				mu.Lock()
				delete(active, id)
				mu.Unlock()
				if ctx.Err() == nil {
					fmt.Printf("🛑 [Docker] Container stopped: %s (%s)\n", name, id[:min(12, len(id))])
				}
			}()

			tailContainerToChan(cCtx, id, tailLines, allLogs, out)
		}()
	}

	labels := []string{"routewarden=true", "routewarden.logs=true"}
	if customLabel != "" {
		labels = []string{customLabel}
	}

	if sockPath := os.Getenv("DOCKER_HOST"); sockPath == "" {
		if fi, err := os.Stat("/var/run/docker.sock"); err == nil && fi.IsDir() {
			fmt.Fprintln(os.Stderr, "⚠️  [Docker] /var/run/docker.sock is a directory, not a Unix domain socket.")
			fmt.Fprintln(os.Stderr, "   On macOS (Docker Desktop), the host socket is located at ~/.docker/run/docker.sock.")
			fmt.Fprintln(os.Stderr, "   Fix: mount -v ~/.docker/run/docker.sock:/var/run/docker.sock")
			fmt.Fprintln(os.Stderr, "   Or enable 'Allow default Docker socket to be used' in Docker Desktop > Settings > Advanced.")
		}
	}

	var lastErrStr string
	scan := func() {
		for _, l := range labels {
			cmd := exec.CommandContext(ctx, "docker", "ps", "--filter", "status=running", "--filter", "label="+l, "--format", "{{.ID}}\t{{.Names}}")
			outBytes, err := cmd.CombinedOutput()
			if err != nil {
				if ctx.Err() == nil {
					errStr := strings.TrimSpace(string(outBytes))
					if errStr == "" {
						errStr = err.Error()
					}
					if errStr != lastErrStr {
						lastErrStr = errStr
						fmt.Fprintf(os.Stderr, "⚠️  [Docker] Discovery error with label %q: %s\n", l, errStr)
					}
				}
				continue
			}
			lastErrStr = ""
			for _, line := range strings.Split(strings.TrimSpace(string(outBytes)), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, "\t")
				if len(parts) >= 1 && parts[0] != "" {
					name := parts[0]
					if len(parts) >= 2 {
						name = parts[1]
					}
					mu.Lock()
					_, isStreaming := active[parts[0]]
					mu.Unlock()
					if !isStreaming {
						startStream(parts[0], name)
					}
				}
			}
		}
	}

	// Scan immediately on startup
	scan()

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
			scan()
		}
	}
}

func sendBatchWithRetry(ctx context.Context, client *http.Client, eventsURL, agentToken, agentID, hostname string, serverPubKey *ecdh.PublicKey, batch []string) error {
	if len(batch) == 0 {
		return nil
	}

	payloadObj := pushPayload{
		AgentID:  agentID,
		Hostname: hostname,
		Events:   batch,
	}
	payloadBytes, err := json.Marshal(payloadObj)
	if err != nil {
		return err
	}

	bodyToSend := payloadBytes
	if serverPubKey != nil {
		encrypted, err := crypto.Encrypt(serverPubKey, payloadBytes)
		if err == nil {
			if encBytes, err := json.Marshal(encrypted); err == nil {
				bodyToSend = encBytes
			}
		}
	}

	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	backoff := 50 * time.Millisecond
	var lastErr error
	for retries := 0; retries < 3; retries++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, eventsURL, bytes.NewReader(bodyToSend))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+agentToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return lastErr
}

func resolveFileList(flags []string, positionalArgs []string) []string {
	var results []string
	seen := make(map[string]bool)

	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if p == "-" {
			if !seen[p] {
				seen[p] = true
				results = append(results, p)
			}
			return
		}
		// Check if it's a directory
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			entries, readErr := os.ReadDir(p)
			if readErr == nil {
				for _, entry := range entries {
					if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".log") || strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".txt")) {
						full := filepath.Join(p, entry.Name())
						if !seen[full] {
							seen[full] = true
							results = append(results, full)
						}
					}
				}
			}
			return
		}
		// Check if it's a glob pattern
		if strings.ContainsAny(p, "*?[]") {
			matches, err := filepath.Glob(p)
			if err == nil && len(matches) > 0 {
				for _, m := range matches {
					if !seen[m] {
						seen[m] = true
						results = append(results, m)
					}
				}
			}
			return
		}
		if !seen[p] {
			seen[p] = true
			results = append(results, p)
		}
	}

	for _, item := range flags {
		parts := strings.Split(item, ",")
		for _, part := range parts {
			addPath(part)
		}
	}

	for _, arg := range positionalArgs {
		parts := strings.Split(arg, ",")
		for _, part := range parts {
			addPath(part)
		}
	}

	return results
}

func resolveContainerList(flags []string) []string {
	var results []string
	seen := make(map[string]bool)
	for _, item := range flags {
		parts := strings.Split(item, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" && !seen[part] {
				seen[part] = true
				results = append(results, part)
			}
		}
	}
	return results
}

func fetchServerPubKey(dashboardURL string) *ecdh.PublicKey {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(dashboardURL, "/") + "/api/v1/pubkey")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil || body.PublicKey == "" {
		return nil
	}
	pk, err := crypto.DecodePublicKey(body.PublicKey)
	if err != nil {
		return nil
	}
	return pk
}
