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
	"regexp"
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
	dockerMode := fs.Bool("docker", false, "Auto-discover and tail Docker containers with label 'routewarden=true'")
	containerName := fs.String("container", "", "Tail a specific Docker container by name or ID")
	fs.StringVar(containerName, "c", "", "Alias for --container")
	customLabel := fs.String("label", "", "Docker label to filter containers (default: routewarden=true)")
	fs.StringVar(customLabel, "l", "", "Alias for --label")
	tailLines := fs.String("tail", "50", "Initial lines to tail from Docker container(s)")
	rawOutput := fs.Bool("raw", false, "Output raw unformatted log lines (ideal for piping into GoAccess or jq)")
	verdictFilter := fs.String("verdict", "", "Filter events by verdict (BLOCK, ALLOW, TARPIT)")
	ipFilter := fs.String("ip", "", "Filter events by client IP substring")
	pathFilter := fs.String("path", "", "Filter events by request path substring")
	_ = parseFlagsLenient(fs, args)

	// Determine execution mode: file, stdin pipe, or docker auto-discovery
	stat, err := os.Stdin.Stat()
	isStdinPipe := (err == nil && (stat.Mode()&os.ModeCharDevice) == 0)

	useDocker := *dockerMode || *containerName != "" || (*file == "" && !isStdinPipe)

	if useDocker && *file == "" && !isStdinPipe {
		runDockerMonitor(*containerName, *customLabel, *tailLines, *verdictFilter, *ipFilter, *pathFilter, *rawOutput)
		return
	}

	// File or Stdin mode
	var reader io.Reader = os.Stdin
	sourceName := "standard input"

	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file %s: %v\n", *file, err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
		sourceName = *file
	}

	if !*rawOutput {
		fmt.Printf("📡 RouteWarden Threat Monitor — Streaming security events from %s\n", sourceName)
		printFilterNotice(*verdictFilter, *ipFilter, *pathFilter)
	}

	msgChan := make(chan streamMsg, 500)
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			msgChan <- streamMsg{Container: "", Line: scanner.Text()}
		}
		close(msgChan)
	}()

	processLogStream(msgChan, *verdictFilter, *ipFilter, *pathFilter, *rawOutput)
}

func runDockerMonitor(containerName, customLabel, tailLines, verdictFilter, ipFilter, pathFilter string, rawOutput bool) {
	var targets []containerTarget

	if containerName != "" {
		t, err := findDockerContainer(containerName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, *t)
	} else {
		discovered, err := discoverDockerContainers(customLabel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to query Docker daemon: %v\n", err)
			fmt.Fprintln(os.Stderr, "   Ensure the Docker daemon is running and /var/run/docker.sock is accessible.")
			os.Exit(1)
		}
		if len(discovered) == 0 {
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
		targets = discovered
	}

	if !rawOutput {
		fmt.Printf("🐳 RouteWarden Docker Monitor — Auto-discovered %d container(s):\n", len(targets))
		for _, t := range targets {
			fmt.Printf("   • %s (%s)\n", t.Name, t.ID[:12])
		}
		printFilterNotice(verdictFilter, ipFilter, pathFilter)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msgChan := make(chan streamMsg, 1000)
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func(c containerTarget) {
			defer wg.Done()
			streamContainerLogs(ctx, c, tailLines, msgChan)
		}(target)
	}

	// Close msgChan when all streams end
	go func() {
		wg.Wait()
		close(msgChan)
	}()

	processLogStream(msgChan, verdictFilter, ipFilter, pathFilter, rawOutput)
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
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case out <- streamMsg{Container: target.Name, Line: scanner.Text()}:
			}
		}
	}

	streamWg.Add(2)
	go readPipe(stdout)
	go readPipe(stderr)

	streamWg.Wait()
	_ = cmd.Wait()
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

func processLogStream(msgChan <-chan streamMsg, verdictFilter, ipFilter, pathFilter string, rawOutput bool) {
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

		// In raw output mode (for GoAccess / piping), emit the raw log line directly
		if rawOutput {
			fmt.Println(line)
			continue
		}

		// Update metrics
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

		method := ev.Method
		if method == "" {
			method = "GET"
		}

		timeStr := ev.Timestamp
		if timeStr == "" {
			timeStr = time.Now().Format("15:04:05")
		} else if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
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
	// Try parsing as JSON first
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		var ev logEvent
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			return &ev
		}
	}

	// Try parsing as Common / Combined Access Log
	matches := combinedLogRegex.FindStringSubmatch(line)
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
