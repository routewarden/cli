package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
)

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

func (e *logEvent) getIP() string {
	if e.ClientIP != "" {
		return e.ClientIP
	}
	if e.ClientIPAlt != "" {
		return e.ClientIPAlt
	}
	return "-"
}

func (e *logEvent) getPath() string {
	if e.Path != "" {
		return e.Path
	}
	if e.PathAlt != "" {
		return e.PathAlt
	}
	return "/"
}

// getVerdict returns the security enforcement action. If Verdict is empty,
// a status code heuristic is applied (403 -> BLOCK, 429 -> TARPIT).
// Note: application-level 403s/429s without explicit RouteWarden headers
// will also be categorized under these verdicts.
func (e *logEvent) getVerdict() string {
	if e.Verdict != "" {
		return strings.ToUpper(e.Verdict)
	}
	if e.StatusCode == 403 || e.StatusCodeAlt == 403 {
		return "BLOCK"
	}
	if e.StatusCode == 429 || e.StatusCodeAlt == 429 {
		return "TARPIT"
	}
	return "ALLOW"
}

func (e *logEvent) getPattern() string {
	if e.MatchedPattern != "" {
		return e.MatchedPattern
	}
	return e.MatchedRuleAlt
}

func (e *logEvent) getLatency() float64 {
	if e.LatencyMs > 0 {
		return e.LatencyMs
	}
	return e.DurationMsAlt
}

func (e *logEvent) toCombinedLog() string {
	ip := e.getIP()
	if ip == "-" || ip == "" {
		ip = "127.0.0.1"
	}
	path := e.getPath()
	method := e.Method
	if method == "" {
		method = "GET"
	}
	status := e.StatusCode
	if status == 0 {
		status = e.StatusCodeAlt
	}
	if status == 0 {
		switch e.getVerdict() {
		case "BLOCK":
			status = 403
		case "TARPIT":
			status = 429
		default:
			status = 200
		}
	}
	t := time.Now().UTC()
	tsRaw := e.Timestamp
	if tsRaw == "" {
		tsRaw = e.TimestampAlt
	}
	if tsRaw != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, tsRaw); err == nil {
			t = parsed
		} else if parsed, err := time.Parse("2006-01-02 15:04:05", tsRaw); err == nil {
			t = parsed
		}
	}
	timeStr := t.Format("02/Jan/2006:15:04:05 -0700")
	rule := e.getPattern()
	if rule == "" {
		rule = "RouteWarden"
	}
	return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" %d 0 \"-\" \"%s\"", ip, timeStr, method, path, status, rule)
}

type containerTarget struct {
	ID   string
	Name string
}

type streamMsg struct {
	Container string
	Line      string
}

// Regex for standard Combined Apache/Nginx access log
var combinedLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+\S+`)

func handleMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	file := fs.String("file", "", "Log file to read from (default: stdin or auto-discovered docker)")
	fs.StringVar(file, "f", "", "Alias for --file")
	outPath := fs.String("out", "", "Output file to write/append monitored events to (Combined log format)")
	fs.StringVar(outPath, "o", "", "Alias for --out")
	dockerMode := fs.Bool("docker", false, "Auto-discover and tail Docker containers with label 'routewarden=true'")
	containerName := fs.String("container", "", "Tail a specific Docker container by name or ID")
	fs.StringVar(containerName, "c", "", "Alias for --container")
	customLabel := fs.String("label", "", "Docker label to filter containers (default: routewarden=true)")
	fs.StringVar(customLabel, "l", "", "Alias for --label")
	tailLines := fs.String("tail", "50", "Initial lines to tail from Docker container(s)")
	rawOutput := fs.Bool("raw", false, "Output raw unformatted log lines (ideal for piping into external analyzers or jq)")
	waitContainers := fs.Bool("wait", false, "Wait and retry if no matching containers are running initially")
	fs.BoolVar(waitContainers, "w", false, "Alias for --wait")
	verdictFilter := fs.String("verdict", "", "Filter events by verdict (BLOCK, ALLOW, TARPIT)")
	ipFilter := fs.String("ip", "", "Filter events by client IP substring")
	pathFilter := fs.String("path", "", "Filter events by request path substring")
	followMode := fs.Bool("follow", false, "Continuously follow log file for new changes (like tail -f)")
	fs.BoolVar(followMode, "F", false, "Alias for --follow")
	_ = parseFlagsLenient(fs, args)

	if *file == "" && fs.NArg() > 0 && !strings.HasPrefix(fs.Arg(0), "-") {
		*file = fs.Arg(0)
	}

	if !*waitContainers && os.Getenv("RWARDEN_MONITOR_WAIT") == "true" {
		*waitContainers = true
	}

	// Determine execution mode: file, stdin pipe, or docker auto-discovery
	stat, err := os.Stdin.Stat()
	isStdinPipe := (err == nil && (stat.Mode()&os.ModeCharDevice) == 0)

	useDocker := *dockerMode || *containerName != "" || (*file == "" && !isStdinPipe)

	if useDocker && *file == "" && !isStdinPipe {
		runDockerMonitor(*containerName, *customLabel, *tailLines, *verdictFilter, *ipFilter, *pathFilter, *outPath, *rawOutput, *waitContainers)
		return
	}

	if *file != "" {
		if *followMode {
			runFileMonitor(*file, *tailLines, *verdictFilter, *ipFilter, *pathFilter, *outPath, *rawOutput)
			return
		}

		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file %s: %v\n", *file, err)
			os.Exit(1)
		}
		defer f.Close()

		sourceName := *file
		if !*rawOutput {
			fmt.Printf("📡 RouteWarden Threat Monitor — Streaming security events from %s\n", sourceName)
			printFilterNotice(*verdictFilter, *ipFilter, *pathFilter)
		}

		msgChan := make(chan streamMsg, 500)
		go func() {
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
			for scanner.Scan() {
				msgChan <- streamMsg{Container: filepath.Base(*file), Line: scanner.Text()}
			}
			if scanErr := scanner.Err(); scanErr != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Scanner error reading from %s: %v\n", sourceName, scanErr)
			}
			close(msgChan)
		}()

		processLogStream(msgChan, *verdictFilter, *ipFilter, *pathFilter, *outPath, *rawOutput)
		return
	}

	// Stdin mode
	if !*rawOutput {
		fmt.Printf("📡 RouteWarden Threat Monitor — Streaming security events from standard input\n")
		printFilterNotice(*verdictFilter, *ipFilter, *pathFilter)
	}

	msgChan := make(chan streamMsg, 500)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			msgChan <- streamMsg{Container: "", Line: scanner.Text()}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  Scanner error reading from standard input: %v\n", err)
		}
		close(msgChan)
	}()

	processLogStream(msgChan, *verdictFilter, *ipFilter, *pathFilter, *outPath, *rawOutput)
}

func runFileMonitor(filePath, tailLines, verdictFilter, ipFilter, pathFilter, outPath string, rawOutput bool) {
	if !rawOutput {
		fmt.Printf("📡 RouteWarden Threat Monitor — Streaming security events from %s\n", filePath)
		printFilterNotice(verdictFilter, ipFilter, pathFilter)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	go func() {
		<-sigChan
		cancel()
	}()

	msgChan := make(chan streamMsg, 500)
	isPattern := strings.ContainsAny(filePath, "*?[]")

	var mu sync.Mutex
	active := make(map[string]context.CancelFunc)
	var streamWg sync.WaitGroup

	startFileStream := func(p string) {
		mu.Lock()
		if _, exists := active[p]; exists {
			mu.Unlock()
			return
		}
		fCtx, fCancel := context.WithCancel(ctx)
		active[p] = fCancel
		mu.Unlock()

		streamWg.Add(1)
		go func() {
			defer func() {
				mu.Lock()
				delete(active, p)
				mu.Unlock()
				streamWg.Done()
			}()
			streamFileLogs(fCtx, p, tailLines, msgChan, rawOutput)
		}()
	}

	// Resolve initial files
	if isPattern {
		matches, _ := filepath.Glob(filePath)
		for _, m := range matches {
			startFileStream(m)
		}
	} else if fi, err := os.Stat(filePath); err == nil && fi.IsDir() {
		entries, _ := os.ReadDir(filePath)
		for _, entry := range entries {
			if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".log") || strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".txt")) {
				startFileStream(filepath.Join(filePath, entry.Name()))
			}
		}
	} else {
		startFileStream(filePath)
	}

	// Dynamic observer: continuously watch for new logfiles if pattern or directory
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for _, c := range active {
					c()
				}
				mu.Unlock()
				return
			case <-ticker.C:
				if isPattern {
					matches, _ := filepath.Glob(filePath)
					for _, m := range matches {
						mu.Lock()
						_, running := active[m]
						mu.Unlock()
						if !running {
							if !rawOutput {
								fmt.Printf("📄 [File] Attached to new log file: %s\n", m)
							}
							startFileStream(m)
						}
					}
				} else if fi, err := os.Stat(filePath); err == nil && fi.IsDir() {
					entries, _ := os.ReadDir(filePath)
					for _, entry := range entries {
						if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".log") || strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".txt")) {
							full := filepath.Join(filePath, entry.Name())
							mu.Lock()
							_, running := active[full]
							mu.Unlock()
							if !running {
								if !rawOutput {
									fmt.Printf("📄 [File] Attached to new log file: %s\n", full)
								}
								startFileStream(full)
							}
						}
					}
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		streamWg.Wait()
		close(msgChan)
	}()

	processLogStream(msgChan, verdictFilter, ipFilter, pathFilter, outPath, rawOutput)
}

func streamFileLogs(ctx context.Context, filePath, tailLines string, out chan<- streamMsg, rawOutput bool) {
	sourceLabel := filepath.Base(filePath)

	var f *os.File
	for {
		var err error
		f, err = os.Open(filePath)
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
				fmt.Fprintf(os.Stderr, "⚠️ [File %s] Scanner error during initial tail: %v\n", filePath, scanErr)
			}
			if len(initialLines) > nTail {
				initialLines = initialLines[len(initialLines)-nTail:]
			}
			for _, l := range initialLines {
				select {
				case <-ctx.Done():
					return
				case out <- streamMsg{Container: sourceLabel, Line: l}:
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
				case out <- streamMsg{Container: sourceLabel, Line: line}:
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

			fi, statErr := os.Stat(filePath)
			if statErr != nil {
				// File may be temporarily moved or deleted by logrotate
				continue
			}

			// 1. Check for in-place truncation
			if fi.Size() < offset {
				if !rawOutput {
					fmt.Printf("✂️  [File] Detected truncation for %s (size %d < offset %d), rewinding to beginning\n", sourceLabel, fi.Size(), offset)
				}
				_, _ = f.Seek(0, io.SeekStart)
				offset = 0
				pendingLine = ""
				reader.Reset(f)
				continue
			}

			// 2. Check for log rotation (different inode/identity)
			curFi, _ := f.Stat()
			if curFi != nil && !os.SameFile(fi, curFi) {
				if !rawOutput {
					fmt.Printf("🔄 [File] Detected rotation for %s, re-attaching to new file\n", sourceLabel)
				}
				// Drain any remaining lines from the rotated file
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
							case out <- streamMsg{Container: sourceLabel, Line: trimmed}:
							}
						}
					}
					if rErr != nil {
						break
					}
				}

				newFile, openErr := os.Open(filePath)
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

func runDockerMonitor(containerName, customLabel, tailLines, verdictFilter, ipFilter, pathFilter, outPath string, rawOutput, waitMode bool) {
	var targets []containerTarget

	if containerName != "" {
		for {
			t, err := findDockerContainer(containerName)
			if err != nil {
				if waitMode {
					time.Sleep(3 * time.Second)
					continue
				}
				fmt.Fprintf(os.Stderr, "❌ %v\n", err)
				os.Exit(1)
			}
			targets = append(targets, *t)
			break
		}
	} else {
		for {
			discovered, err := discoverDockerContainers(customLabel)
			if err != nil {
				if waitMode {
					time.Sleep(3 * time.Second)
					continue
				}
				fmt.Fprintf(os.Stderr, "❌ Failed to query Docker daemon: %v\n", err)
				fmt.Fprintln(os.Stderr, "   Ensure the Docker daemon is running and /var/run/docker.sock is accessible.")
				os.Exit(1)
			}
			if len(discovered) > 0 {
				targets = discovered
				break
			}
			if !waitMode {
				labelName := "routewarden=true"
				if customLabel != "" {
					labelName = customLabel
				}
				fmt.Fprintf(os.Stderr, "🔍 No running Docker containers found with label %q\n\n", labelName)
				fmt.Fprintln(os.Stderr, "To enable auto-monitoring, add the label to your services in docker-compose.yaml:")
				fmt.Fprintln(os.Stderr, "  services:")
				fmt.Fprintln(os.Stderr, "    traefik:")
				fmt.Fprintln(os.Stderr, "      labels:")
				fmt.Fprintln(os.Stderr, "        - \"routewarden=true\"")
				fmt.Fprintln(os.Stderr, "\nOr monitor a specific container by name:")
				fmt.Fprintln(os.Stderr, "  rwarden monitor --container <container-name>")
				os.Exit(1)
			}
		}
	}

	if !rawOutput {
		fmt.Printf("🐳 RouteWarden Docker Monitor — Auto-discovered %d container(s):\n", len(targets))
		for _, t := range targets {
			idShort := t.ID
			if len(idShort) > 12 {
				idShort = idShort[:12]
			}
			fmt.Printf("   • %s (%s)\n", t.Name, idShort)
		}
		printFilterNotice(verdictFilter, ipFilter, pathFilter)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msgChan := make(chan streamMsg, 1000)
	var mu sync.Mutex
	active := make(map[string]context.CancelFunc)

	startStream := func(target containerTarget, tail string) {
		mu.Lock()
		if _, exists := active[target.ID]; exists {
			mu.Unlock()
			return
		}
		cCtx, cancelFunc := context.WithCancel(ctx)
		active[target.ID] = cancelFunc
		mu.Unlock()

		go func() {
			defer func() {
				mu.Lock()
				delete(active, target.ID)
				mu.Unlock()
				if ctx.Err() == nil && !rawOutput {
					idShort := target.ID
					if len(idShort) > 12 {
						idShort = idShort[:12]
					}
					fmt.Printf("🛑 [Docker] Container stopped: %s (%s)\n", target.Name, idShort)
				}
			}()

			streamContainerLogs(cCtx, target, tail, msgChan)
		}()
	}

	for _, target := range targets {
		startStream(target, tailLines)
	}

	// Dynamic observer: continuously watch for containers starting or stopping
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				mu.Lock()
				for _, c := range active {
					c()
				}
				mu.Unlock()
				return
			case <-ticker.C:
				if containerName != "" {
					if t, err := findDockerContainer(containerName); err == nil {
						mu.Lock()
						_, isStreaming := active[t.ID]
						mu.Unlock()
						if !isStreaming {
							if !rawOutput {
								idShort := t.ID
								if len(idShort) > 12 {
									idShort = idShort[:12]
								}
								fmt.Printf("🐳 [Docker] Attached to container: %s (%s)\n", t.Name, idShort)
							}
							startStream(*t, "50")
						}
					}
				} else {
					if discovered, err := discoverDockerContainers(customLabel); err == nil {
						for _, c := range discovered {
							mu.Lock()
							_, isStreaming := active[c.ID]
							mu.Unlock()
							if !isStreaming {
								if !rawOutput {
									idShort := c.ID
									if len(idShort) > 12 {
										idShort = idShort[:12]
									}
									fmt.Printf("🐳 [Docker] Attached to container: %s (%s)\n", c.Name, idShort)
								}
								startStream(c, "50")
							}
						}
					}
				}
			}
		}
	}()

	processLogStream(msgChan, verdictFilter, ipFilter, pathFilter, outPath, rawOutput)
}

func streamContainerLogs(ctx context.Context, target containerTarget, tailLines string, out chan<- streamMsg) {
	args := []string{"logs", "-f", "--tail", tailLines, target.ID}
	cmd := exec.CommandContext(ctx, "docker", args...)

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

	var streamWg sync.WaitGroup
	readPipe := func(r io.Reader) {
		defer streamWg.Done()
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case out <- streamMsg{Container: target.Name, Line: scanner.Text()}:
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "⚠️  [Docker] Scanner error for container %s: %v\n", target.Name, err)
		}
	}

	streamWg.Add(2)
	go readPipe(stdout)
	go readPipe(stderr)

	streamWg.Wait()
	_ = cmd.Wait()
}

func discoverDockerContainers(customLabel string) ([]containerTarget, error) {
	if sockPath := os.Getenv("DOCKER_HOST"); sockPath == "" {
		if fi, err := os.Stat("/var/run/docker.sock"); err == nil && fi.IsDir() {
			fmt.Fprintln(os.Stderr, "⚠️  [Docker] /var/run/docker.sock is a directory, not a Unix domain socket.")
			fmt.Fprintln(os.Stderr, "   On macOS (Docker Desktop), the host socket is located at ~/.docker/run/docker.sock.")
			fmt.Fprintln(os.Stderr, "   Fix: mount -v ~/.docker/run/docker.sock:/var/run/docker.sock")
			fmt.Fprintln(os.Stderr, "   Or enable 'Allow default Docker socket to be used' in Docker Desktop > Settings > Advanced.")
		}
	}

	labels := []string{"routewarden=true", "routewarden.logs=true"}
	if customLabel != "" {
		labels = []string{customLabel}
	}

	seen := make(map[string]bool)
	var containers []containerTarget

	var lastErr error
	for _, l := range labels {
		cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "label="+l, "--format", "{{.ID}}\t{{.Names}}")
		out, err := cmd.CombinedOutput()
		if err != nil {
			errStr := strings.TrimSpace(string(out))
			if errStr == "" {
				errStr = err.Error()
			}
			fmt.Fprintf(os.Stderr, "⚠️  [Docker] Failed to query containers with label %q: %s\n", l, errStr)
			lastErr = err
			continue
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
	// Only propagate an error if every label query failed and we found nothing.
	if len(containers) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return containers, nil
}

func findDockerContainer(nameOrID string) (*containerTarget, error) {
	cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "name="+nameOrID, "--format", "{{.ID}}\t{{.Names}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker query error: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		name := parts[0]
		if len(parts) >= 2 {
			name = parts[1]
		}
		return &containerTarget{ID: parts[0], Name: name}, nil
	}
	return nil, fmt.Errorf("container %q not found or not in running state", nameOrID)
}

func printFilterNotice(verdictFilter, ipFilter, pathFilter string) {
	if verdictFilter != "" {
		fmt.Printf("   Filter: Verdict = %s\n", strings.ToUpper(verdictFilter))
	}
	if ipFilter != "" {
		fmt.Printf("   Filter: IP contains %q\n", ipFilter)
	}
	if pathFilter != "" {
		fmt.Printf("   Filter: Path contains %q\n", pathFilter)
	}
	fmt.Println("   Press Ctrl+C to stop and view aggregate threat summary.")
	fmt.Println(strings.Repeat("─", 80))
}

func processLogStream(msgChan <-chan streamMsg, verdictFilter, ipFilter, pathFilter, outPath string, rawOutput bool) {
	var outWriter *os.File
	if outPath != "" {
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file %s: %v\n", outPath, err)
			os.Exit(1)
		}
		defer f.Close()
		outWriter = f
	}

	var statsMu sync.Mutex
	totalEvents := 0
	blockedEvents := 0
	allowedEvents := 0
	tarpitEvents := 0
	uniqueIPs := make(map[string]bool)
	containerHits := make(map[string]int)
	containerBlocks := make(map[string]int)
	topPaths := make(map[string]int)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		if rawOutput {
			os.Exit(0)
		}
		statsMu.Lock()
		defer statsMu.Unlock()
		fmt.Println("\n" + strings.Repeat("─", 80))
		fmt.Println("📊 Stream Monitoring Summary:")
		fmt.Printf("   Total Events Processed: %d\n", totalEvents)
		blockPct := 0.0
		if totalEvents > 0 {
			blockPct = (float64(blockedEvents) / float64(totalEvents)) * 100.0
		}
		fmt.Printf("   Blocked Threats:        %d (%.1f%%)\n", blockedEvents, blockPct)
		fmt.Printf("   Allowed Requests:       %d\n", allowedEvents)
		fmt.Printf("   Tarpitted Requests:     %d\n", tarpitEvents)
		fmt.Printf("   Unique Client IPs:      %d\n", len(uniqueIPs))

		if len(containerHits) > 0 {
			fmt.Println("\n   Traffic per Container:")
			for c, hits := range containerHits {
				bl := containerBlocks[c]
				fmt.Printf("     • %-20s: %d events (%d blocked)\n", c, hits, bl)
			}
		}

		if len(topPaths) > 0 {
			fmt.Println("\n   Top Target Paths:")
			count := 0
			for p, c := range topPaths {
				fmt.Printf("     • %-35s (%d hits)\n", p, c)
				count++
				if count >= 5 {
					break
				}
			}
		}
		fmt.Println(strings.Repeat("─", 80))
		os.Exit(0)
	}()

	for msg := range msgChan {
		line := strings.TrimSpace(msg.Line)
		if line == "" {
			continue
		}

		ev := parseLogLine(line)
		if ev == nil {
			if rawOutput {
				fmt.Println(line)
			}
			if outWriter != nil {
				_, _ = outWriter.WriteString(line + "\n")
				_ = outWriter.Sync()
			}
			continue
		}

		verdict := ev.getVerdict()
		ip := ev.getIP()
		path := ev.getPath()

		// Apply filters
		if verdictFilter != "" && !strings.EqualFold(verdict, verdictFilter) {
			continue
		}
		if ipFilter != "" && !strings.Contains(ip, ipFilter) {
			continue
		}
		if pathFilter != "" && !strings.Contains(path, pathFilter) {
			continue
		}

		// In raw output mode (for external analyzers / piping), emit standard Combined log line
		if rawOutput {
			outLine := line
			if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
				outLine = ev.toCombinedLog()
			}
			fmt.Println(outLine)
			if outWriter != nil {
				_, _ = outWriter.WriteString(outLine + "\n")
				_ = outWriter.Sync()
			}
			continue
		}

		if outWriter != nil {
			outLine := line
			if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
				outLine = ev.toCombinedLog()
			}
			_, _ = outWriter.WriteString(outLine + "\n")
			_ = outWriter.Sync()
		}

		// Update metrics
		statsMu.Lock()
		totalEvents++
		uniqueIPs[ip] = true
		topPaths[path]++
		if msg.Container != "" {
			containerHits[msg.Container]++
		}

		badge := "🛡️ ALLOW "
		switch verdict {
		case "BLOCK":
			badge = "🛑 BLOCK "
			blockedEvents++
			if msg.Container != "" {
				containerBlocks[msg.Container]++
			}
		case "TARPIT":
			badge = "⏳ TARPIT"
			tarpitEvents++
		default:
			allowedEvents++
		}
		statsMu.Unlock()

		method := ev.Method
		if method == "" {
			method = "GET"
		}

		timeStr := ev.Timestamp
		if timeStr == "" {
			timeStr = ev.TimestampAlt
		}
		if timeStr == "" {
			timeStr = time.Now().Format("15:04:05")
		} else if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
			timeStr = t.Format("15:04:05")
		} else if t, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
			timeStr = t.Format("15:04:05")
		}

		prefix := ""
		if msg.Container != "" {
			prefix = fmt.Sprintf("[%s] ", msg.Container)
		}

		extra := ""
		if ev.getPattern() != "" {
			extra += fmt.Sprintf(" [Rule: %s]", ev.getPattern())
		}
		if ev.getLatency() > 0 {
			extra += fmt.Sprintf(" (%.2fms)", ev.getLatency())
		}

		fmt.Printf("%s[%s] %s %-15s -> %-5s %-30s%s\n", prefix, timeStr, badge, ip, method, path, extra)
	}
}

func parseLogLine(line string) *logEvent {
	trimmed := strings.TrimRight(line, " \r\t")
	// Try parsing as JSON first
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		var ev logEvent
		if err := json.Unmarshal([]byte(trimmed), &ev); err == nil {
			return &ev
		}
	}

	// Try parsing as Common / Combined Access Log
	matches := combinedLogRegex.FindStringSubmatch(trimmed)
	if len(matches) == 6 {
		statusCode := 200
		fmt.Sscanf(matches[5], "%d", &statusCode)
		return &logEvent{
			ClientIP:   matches[1],
			Timestamp:  matches[2],
			Method:     matches[3],
			Path:       matches[4],
			StatusCode: statusCode,
		}
	}

	return nil
}
