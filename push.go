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
		if err := sendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, eventsToPush); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to push event(s): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Successfully pushed %d event(s) to RouteWarden dashboard\n", len(eventsToPush))
		return
	}

	// ─── 2. Manual Piped Push via STDIN (--stdin or -f -) ─────────────────────
	if hasStdin {
		client := &http.Client{Timeout: 10 * time.Second}
		eventsURL := dashboardURL + "/api/v1/events"
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)

		var buffer []string
		totalPushed := 0

		flush := func() error {
			if len(buffer) == 0 {
				return nil
			}
			batch := buffer
			buffer = nil
			if err := sendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, batch); err != nil {
				return err
			}
			totalPushed += len(batch)
			return nil
		}

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				buffer = append(buffer, line)
				if len(buffer) >= *batchSize {
					if err := flush(); err != nil {
						fmt.Fprintf(os.Stderr, "❌ Failed to push event batch: %v\n", err)
						os.Exit(1)
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error reading from STDIN: %v\n", err)
			os.Exit(1)
		}

		if err := flush(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to push final event batch: %v\n", err)
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
			go tailContainerToChan(ctx, c, *tailLines, eventChan)
		}
	}
	if runDockerDiscovery {
		labelDesc := "'routewarden=true'"
		if *customLabel != "" {
			labelDesc = fmt.Sprintf("'%s'", *customLabel)
		}
		fmt.Printf("  Auto-Discovery:  Watching Docker containers with label %s\n", labelDesc)
		go watchDockerContainersToChan(ctx, *customLabel, *tailLines, eventChan)
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
	ticker := time.NewTicker(*flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(buffer) == 0 {
			return
		}
		batch := buffer
		buffer = nil
		_ = sendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, batch)
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			fmt.Println("\n✅ Remote shipper stopped.")
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
		return
	}
	if err := cmd.Start(); err != nil {
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
		_ = err
	}
}

func tailContainerToChan(ctx context.Context, containerName, tailLines string, out chan<- string) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--tail", tailLines, containerName)
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
			select {
			case <-ctx.Done():
				return
			case out <- scanner.Text():
			}
		}
		if err := scanner.Err(); err != nil {
			_ = err
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

func watchDockerContainersToChan(ctx context.Context, customLabel, tailLines string, out chan<- string) {
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

			tailContainerToChan(cCtx, id, tailLines, out)
		}()
	}

	labels := []string{"routewarden=true", "routewarden.logs=true"}
	if customLabel != "" {
		labels = []string{customLabel}
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
			for _, l := range labels {
				cmd := exec.Command("docker", "ps", "--filter", "status=running", "--filter", "label="+l, "--format", "{{.ID}}\t{{.Names}}")
				outBytes, err := cmd.Output()
				if err != nil {
					continue
				}
				for _, line := range strings.Split(strings.TrimSpace(string(outBytes)), "\n") {
					parts := strings.Split(strings.TrimSpace(line), "\t")
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
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()
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
