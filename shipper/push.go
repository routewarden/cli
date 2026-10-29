package shipper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
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
	"github.com/routewarden/cli/daemon"
)

type pushPayload struct {
	AgentID  string   `json:"agent_id"`
	Hostname string   `json:"hostname"`
	Events   []string `json:"events"`
}

// PushOptions represents parsed flags and resolved environment variables for push.
type PushOptions struct {
	URL               string
	Key               string
	ConfigPath        string
	DockerMode        bool
	DetachMode        bool
	ContainerFlags    []string
	FileFlags         []string
	EventFlags        []string
	StdinMode         bool
	StatusCodesFlag   string
	IncludeFailed     bool
	AllTraffic        bool
	CustomLabel       string
	TailLines         string
	BatchSize         int
	FlushInterval     time.Duration
	MaxQueueSize      int
	DisconnectTimeout time.Duration
	PingInterval      time.Duration
	Verbose           bool
	AllLogs           bool
	PositionalArgs    []string
}

// ParsePushOptions parses command-line flags and environment variables for the push command.
func ParsePushOptions(args []string) (*PushOptions, error) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch strings.ToLower(args[0]) {
		case "up", "start", "run":
			args = args[1:]
		}
	}

	opts := &PushOptions{
		TailLines:         "50",
		BatchSize:         50,
		FlushInterval:     1 * time.Second,
		MaxQueueSize:      10000,
		DisconnectTimeout: 5 * time.Minute,
		PingInterval:      10 * time.Second,
	}

	// Environment variable defaults
	if env := os.Getenv("RW_CONFIG"); env != "" {
		opts.ConfigPath = env
	}
	if env := os.Getenv("RW_DOCKER"); env == "1" || strings.EqualFold(env, "true") {
		opts.DockerMode = true
	}
	if env := os.Getenv("RW_LABEL"); env != "" {
		opts.CustomLabel = env
	}
	if env := os.Getenv("RW_TAIL"); env != "" {
		opts.TailLines = env
	}
	if env := os.Getenv("RW_BATCH_SIZE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v > 0 {
			opts.BatchSize = v
		}
	}
	if env := os.Getenv("RW_FLUSH_INTERVAL"); env != "" {
		if d, err := time.ParseDuration(env); err == nil {
			opts.FlushInterval = d
		}
	}
	if env := os.Getenv("RW_QUEUE_SIZE"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v > 0 {
			opts.MaxQueueSize = v
		}
	}
	if env := os.Getenv("RW_DISCONNECT_TIMEOUT"); env != "" {
		if d, err := time.ParseDuration(env); err == nil {
			opts.DisconnectTimeout = d
		}
	}
	if env := os.Getenv("RW_PING_INTERVAL"); env != "" {
		if d, err := time.ParseDuration(env); err == nil {
			opts.PingInterval = d
		}
	}
	if env := os.Getenv("RW_VERBOSE"); env == "1" || strings.EqualFold(env, "true") {
		opts.Verbose = true
	} else if env := os.Getenv("RW_DEBUG"); env == "1" || strings.EqualFold(env, "true") {
		opts.Verbose = true
	}
	if env := os.Getenv("RW_DETACH"); env == "1" || strings.EqualFold(env, "true") {
		opts.DetachMode = true
	}
	if envURL := os.Getenv("RW_DASHBOARD_URL"); envURL != "" {
		opts.URL = envURL
	} else if envURL := os.Getenv("RW_URL"); envURL != "" {
		opts.URL = envURL
	}
	if envKey := os.Getenv("RW_AGENT_KEY"); envKey != "" {
		opts.Key = envKey
	} else if envKey := os.Getenv("RW_KEY"); envKey != "" {
		opts.Key = envKey
	}
	if env := os.Getenv("RW_STATUS"); env != "" {
		opts.StatusCodesFlag = env
	} else if env := os.Getenv("RW_STATUS_CODES"); env != "" {
		opts.StatusCodesFlag = env
	} else if env := os.Getenv("RW_INCLUDE_STATUS"); env != "" {
		opts.StatusCodesFlag = env
	}
	if env := os.Getenv("RW_INCLUDE_FAILED"); env == "1" || strings.EqualFold(env, "true") {
		opts.IncludeFailed = true
		if opts.StatusCodesFlag == "" {
			opts.StatusCodesFlag = "400-599"
		}
	}
	if env := os.Getenv("RW_ALL_TRAFFIC"); env == "1" || strings.EqualFold(env, "true") {
		opts.AllTraffic = true
	}
	if env := os.Getenv("RW_ALL_LOGS"); env == "1" || strings.EqualFold(env, "true") {
		opts.AllLogs = true
	}

	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	fs.StringVar(&opts.URL, "url", opts.URL, "RouteWarden dashboard URL (overrides registered config)")
	fs.StringVar(&opts.URL, "u", opts.URL, "Alias for --url")
	fs.StringVar(&opts.Key, "key", opts.Key, "Remote agent authentication key (overrides registered config)")
	fs.StringVar(&opts.Key, "k", opts.Key, "Alias for --key")
	fs.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "Custom path to agent configuration (default: ~/.routewarden/agent.json)")
	fs.BoolVar(&opts.DockerMode, "docker", opts.DockerMode, "Auto-discover and tail Docker containers with label 'routewarden=true'")
	fs.BoolVar(&opts.DetachMode, "detach", opts.DetachMode, "Run remote shipper in background (detached) mode")
	fs.BoolVar(&opts.DetachMode, "d", opts.DetachMode, "Alias for --detach")

	var containerFlags StringSlice
	fs.Var(&containerFlags, "container", "Tail specific Docker container(s) by name or ID (repeatable or comma-separated)")
	fs.Var(&containerFlags, "c", "Alias for --container")

	var fileFlags StringSlice
	fs.Var(&fileFlags, "file", "Log file(s) to monitor and push (repeatable, comma-separated, or glob pattern)")
	fs.Var(&fileFlags, "f", "Alias for --file")

	var eventFlags StringSlice
	fs.Var(&eventFlags, "event", "Push one or more specific event strings directly (repeatable)")
	fs.Var(&eventFlags, "e", "Alias for --event")

	fs.BoolVar(&opts.StdinMode, "stdin", false, "Read and push events line-by-line from STDIN")
	fs.StringVar(&opts.StatusCodesFlag, "status", opts.StatusCodesFlag, "Forward HTTP requests matching status codes or ranges (e.g. '400-599, 301', '4xx, 5xx')")
	fs.StringVar(&opts.StatusCodesFlag, "s", opts.StatusCodesFlag, "Alias for --status")
	fs.StringVar(&opts.StatusCodesFlag, "status-codes", opts.StatusCodesFlag, "Alias for --status")
	fs.StringVar(&opts.StatusCodesFlag, "include-status", opts.StatusCodesFlag, "Alias for --status")
	fs.BoolVar(&opts.IncludeFailed, "include-failed", opts.IncludeFailed, "Legacy alias: forward all failed HTTP requests (status >= 400, equivalent to --status 400-599)")
	fs.BoolVar(&opts.IncludeFailed, "F", opts.IncludeFailed, "Alias for --include-failed")
	fs.BoolVar(&opts.AllTraffic, "all-traffic", opts.AllTraffic, "Include all HTTP traffic (both successful 2xx/3xx and failed 4xx/5xx)")
	fs.StringVar(&opts.CustomLabel, "label", opts.CustomLabel, "Docker label to filter containers (default: routewarden=true)")
	fs.StringVar(&opts.CustomLabel, "l", opts.CustomLabel, "Alias for --label")
	fs.StringVar(&opts.TailLines, "tail", opts.TailLines, "Initial lines to tail from Docker container(s) and log file(s)")
	fs.IntVar(&opts.BatchSize, "batch-size", opts.BatchSize, "Maximum events to buffer before flushing")
	fs.DurationVar(&opts.FlushInterval, "flush-interval", opts.FlushInterval, "Maximum duration to buffer events before flushing")
	fs.IntVar(&opts.MaxQueueSize, "queue-size", opts.MaxQueueSize, "Maximum events to buffer in memory while disconnected or waiting to flush")
	fs.DurationVar(&opts.DisconnectTimeout, "disconnect-timeout", opts.DisconnectTimeout, "Duration disconnected from dashboard before dropping stale events to protect memory")
	fs.DurationVar(&opts.PingInterval, "ping-interval", opts.PingInterval, "Interval between connection health pings when connected")
	fs.BoolVar(&opts.Verbose, "verbose", opts.Verbose, "Enable verbose event-level logging")
	fs.BoolVar(&opts.Verbose, "v", opts.Verbose, "Alias for --verbose")
	fs.BoolVar(&opts.AllLogs, "all-logs", opts.AllLogs, "Ship all container lines without filtering for RouteWarden logs")

	if err := ParseFlagsLenient(fs, args); err != nil {
		return nil, err
	}

	if opts.IncludeFailed && opts.StatusCodesFlag == "" {
		opts.StatusCodesFlag = "400-599"
	}

	opts.ContainerFlags = []string(containerFlags)
	opts.FileFlags = []string(fileFlags)
	opts.EventFlags = []string(eventFlags)
	opts.PositionalArgs = fs.Args()

	return opts, nil
}

// ResolvedPushConfig holds configuration values after resolving precedence across
// CLI flags, environment variables, registered agent configuration, and defaults.
type ResolvedPushConfig struct {
	DashboardURL    string
	AgentToken      string
	AgentID         string
	AgentName       string
	ServerPubKeyStr string
	StatusCodesFlag string
	IncludeFailed   bool
	AllTraffic      bool
	AllLogs         bool
	FilterOpts      FilterOptions
}

// ResolvePushConfig resolves configuration following strict precedence:
// 1. CLI Flags (Highest)
// 2. Environment Variables
// 3. Agent Configuration File (agent.json)
// 4. Default Fallbacks (Lowest)
func ResolvePushConfig(opts *PushOptions, agentCfg *AgentConfig) ResolvedPushConfig {
	res := ResolvedPushConfig{
		StatusCodesFlag: opts.StatusCodesFlag,
		IncludeFailed:   opts.IncludeFailed,
		AllTraffic:      opts.AllTraffic,
		AllLogs:         opts.AllLogs,
	}

	if agentCfg != nil {
		res.DashboardURL = agentCfg.DashboardURL
		res.AgentToken = agentCfg.AgentToken
		res.AgentID = agentCfg.AgentID
		res.AgentName = agentCfg.AgentName
		res.ServerPubKeyStr = agentCfg.ServerPublicKey
		if res.StatusCodesFlag == "" {
			res.StatusCodesFlag = agentCfg.StatusCodes
		}
		if !res.IncludeFailed && agentCfg.IncludeFailed {
			res.IncludeFailed = true
		}
		if !res.AllTraffic && agentCfg.AllTraffic {
			res.AllTraffic = true
		}
		if !res.AllLogs && agentCfg.AllLogs {
			res.AllLogs = true
		}
	}

	if opts.URL != "" {
		res.DashboardURL = strings.TrimRight(opts.URL, "/")
	}
	if opts.Key != "" {
		res.AgentToken = opts.Key
	}

	if res.StatusCodesFlag == "" && res.IncludeFailed {
		res.StatusCodesFlag = "400-599"
	}

	statusFilter := ParseStatusCodeFilter(res.StatusCodesFlag)
	res.FilterOpts = FilterOptions{
		StatusCodes:   statusFilter,
		IncludeFailed: res.IncludeFailed || len(statusFilter) > 0,
		AllTraffic:    res.AllTraffic,
		AllLogs:       res.AllLogs,
	}

	return res
}

func HandlePush(args []string, version string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch strings.ToLower(args[0]) {
		case "status", "ps":
			daemon.Status("push", "RouteWarden Remote Shipper")
			return
		case "stop", "down":
			_, _ = daemon.Stop("push", "RouteWarden Remote Shipper")
			return
		case "help":
			fmt.Println(`RouteWarden Push — Remote Security Log Shipper

Usage:
  rwarden push [command] [flags]

Commands:
  status, ps           Check running status of remote shipper
  stop, down           Stop running remote shipper daemon

Flags:
  --url, -u            RouteWarden dashboard URL
  --key, -k            Remote agent authentication key
  --config             Custom path to agent configuration
  --docker             Auto-discover Docker containers with 'routewarden=true'
  --container, -c      Tail specific Docker container(s)
  --file, -f           Log file(s) to monitor and push (or '-' for STDIN)
  --event, -e          Push one or more specific event strings directly
  --status, -s         Forward HTTP requests matching status codes or ranges (e.g. '400-599, 301', '4xx, 5xx')
  --all-traffic        Include all HTTP reverse proxy traffic (including 200 OK)
  --detach, -d         Run remote shipper in background (detached) mode
  --verbose, -v        Enable verbose event-level logging`)
			return
		case "up", "start", "run":
			args = args[1:]
		}
	}

	opts, err := ParsePushOptions(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	urlFlag := &opts.URL
	keyFlag := &opts.Key
	configPath := &opts.ConfigPath
	dockerMode := &opts.DockerMode
	detachMode := &opts.DetachMode
	stdinMode := &opts.StdinMode
	statusCodesFlag := &opts.StatusCodesFlag
	includeFailed := &opts.IncludeFailed
	allTraffic := &opts.AllTraffic
	customLabel := &opts.CustomLabel
	tailLines := &opts.TailLines
	batchSize := &opts.BatchSize
	flushInterval := &opts.FlushInterval
	maxQueueSize := &opts.MaxQueueSize
	disconnectTimeout := &opts.DisconnectTimeout
	pingInterval := &opts.PingInterval
	verbose := &opts.Verbose
	allLogs := &opts.AllLogs
	fileFlags := StringSlice(opts.FileFlags)
	containerFlags := StringSlice(opts.ContainerFlags)
	eventFlags := StringSlice(opts.EventFlags)

	filesToMonitor := ResolveFileList(fileFlags, opts.PositionalArgs)
	containersToTail := ResolveContainerList(containerFlags)

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
		_ = daemon.SpawnDetached("push", "RouteWarden Remote Shipper", append([]string{"push"}, args...), 0, "")
		return
	}

	if os.Getenv("_RW_DETACHED") == "1" {
		defer daemon.RemovePID("push")
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
	agentCfg, err := LoadAgentConfig(*configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "❌ Failed to load agent configuration: %v\n", err)
			if *urlFlag == "" || *keyFlag == "" {
				os.Exit(1)
			}
		} else if *urlFlag == "" || *keyFlag == "" {
			fmt.Fprintln(os.Stderr, "❌ RouteWarden is not registered on this node, and --url / --key were not provided.")
			fmt.Fprintln(os.Stderr, "\nTo register this server, run:")
			fmt.Fprintln(os.Stderr, "  rwarden register --url http://<dashboard-ip>:7890 --key <agent-token>")
			fmt.Fprintln(os.Stderr, "\nOr push directly with flags (or RW_DASHBOARD_URL and RW_AGENT_KEY):")
			fmt.Fprintln(os.Stderr, "  rwarden push --url http://<dashboard-ip>:7890 --key <agent-token> --docker")
			os.Exit(1)
		}
	}

	resolvedCfg := ResolvePushConfig(opts, agentCfg)
	if resolvedCfg.DashboardURL == "" || resolvedCfg.AgentToken == "" {
		fmt.Fprintln(os.Stderr, "❌ RouteWarden is not registered on this node, and --url / --key were not provided.")
		fmt.Fprintln(os.Stderr, "\nTo register this server, run:")
		fmt.Fprintln(os.Stderr, "  rwarden register --url http://<dashboard-ip>:7890 --key <agent-token>")
		fmt.Fprintln(os.Stderr, "\nOr push directly with flags (or RW_DASHBOARD_URL and RW_AGENT_KEY):")
		fmt.Fprintln(os.Stderr, "  rwarden push --url http://<dashboard-ip>:7890 --key <agent-token> --docker")
		os.Exit(1)
	}

	dashboardURL := resolvedCfg.DashboardURL
	agentToken := resolvedCfg.AgentToken
	agentID := resolvedCfg.AgentID
	agentName := resolvedCfg.AgentName
	serverPubKeyStr := resolvedCfg.ServerPubKeyStr
	*statusCodesFlag = resolvedCfg.StatusCodesFlag
	*includeFailed = resolvedCfg.IncludeFailed
	*allTraffic = resolvedCfg.AllTraffic
	*allLogs = resolvedCfg.AllLogs

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
		if err := SendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, eventsToPush); err != nil {
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
			if err := SendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, serverPubKey, batch); err != nil {
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
	fmt.Printf("  Offline Queue:   Max=%d, Timeout=%s\n", *maxQueueSize, *disconnectTimeout)
	filterOpts := resolvedCfg.FilterOpts
	statusFilter := filterOpts.StatusCodes

	if *allLogs {
		fmt.Println("  Filter:          Disabled (--all-logs: shipping all raw lines)")
	} else if *allTraffic {
		fmt.Println("  Filter:          All HTTP traffic (--all-traffic: security + 2xx/3xx/4xx/5xx)")
	} else if len(statusFilter) > 0 {
		fmt.Printf("  Filter:          Security events + HTTP status [%s]\n", statusFilter.String())
	} else if *includeFailed {
		fmt.Println("  Filter:          Security events + failed HTTP calls (--include-failed: 4xx/5xx)")
	} else {
		fmt.Println("  Filter:          Security events only (blocks, tarpits & matched rules)")
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
			go TailFileFilteredToChan(ctx, f, *tailLines, filterOpts, eventChan)
		}
	}
	if len(containersToTail) > 0 {
		for _, c := range containersToTail {
			fmt.Printf("  Container:       %s\n", c)
			go func(containerName string) {
				currentTail := *tailLines
				for {
					TailContainerWithFilterOptsToChan(ctx, containerName, currentTail, filterOpts, eventChan)
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
						currentTail = "0"
					}
				}
			}(c)
		}
	}
	if runDockerDiscovery {
		labelDesc := "'routewarden=true'"
		if *customLabel != "" {
			labelDesc = fmt.Sprintf("'%s'", *customLabel)
		}
		fmt.Printf("  Auto-Discovery:  Watching Docker containers with label %s\n", labelDesc)
		go WatchDockerContainersWithFilterOptsToChan(ctx, *customLabel, *tailLines, filterOpts, eventChan)
	}

	// Dynamic observer: continuously watch for new log files matching glob patterns or directories
	var hasGlobOrDir bool
	for _, flagVal := range append(append([]string{}, fileFlags...), opts.PositionalArgs...) {
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
					current := ResolveFileList(fileFlags, opts.PositionalArgs)
					for _, f := range current {
						if f == "-" {
							continue
						}
						if !monitored[f] {
							monitored[f] = true
							fmt.Printf("📄 [File] Attached to new log file: %s\n", f)
							go TailFileFilteredToChan(ctx, f, *tailLines, filterOpts, eventChan)
						}
					}
				}
			}
		}()
	}
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("Press Ctrl+C to stop.")

	// Connection & Key state
	var (
		connMu            sync.RWMutex
		isConnected       bool
		lastConnectedTime = time.Now()
		currentPubKey     = serverPubKey
		reconnectSignal   = make(chan struct{}, 1)
	)

	RegisterKeyUpdateCallback(func(pk *ecdh.PublicKey) {
		connMu.Lock()
		currentPubKey = pk
		connMu.Unlock()
	})

	setConnected := func(conn bool, pk *ecdh.PublicKey) bool {
		connMu.Lock()
		defer connMu.Unlock()
		prev := isConnected
		isConnected = conn
		if conn {
			lastConnectedTime = time.Now()
			if pk != nil {
				currentPubKey = pk
			}
		}
		return prev != conn
	}

	getConnState := func() (bool, time.Time, *ecdh.PublicKey) {
		connMu.RLock()
		defer connMu.RUnlock()
		return isConnected, lastConnectedTime, currentPubKey
	}

	pingClient := &http.Client{Timeout: 5 * time.Second}

	// Initial probe to establish connection state
	initRes := PingDashboard(ctx, pingClient, dashboardURL, agentToken, hostname)
	if initRes.Connected {
		setConnected(true, initRes.ServerPubKey)
		fmt.Printf("[%s] 🟢 Connected to RouteWarden dashboard (%s)\n", time.Now().Format("15:04:05"), dashboardURL)
	} else {
		setConnected(false, nil)
		fmt.Fprintf(os.Stderr, "[%s] ⚠️ Dashboard currently unreachable (%v). Starting in offline queuing mode...\n", time.Now().Format("15:04:05"), initRes.Err)
	}

	// Start Connection Health & Ping supervisor
	go func() {
		for {
			conn, _, _ := getConnState()
			interval := *pingInterval
			if !conn {
				interval = 2 * time.Second
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				res := PingDashboard(ctx, pingClient, dashboardURL, agentToken, hostname)
				if res.Connected {
					wasChanged := setConnected(true, res.ServerPubKey)
					if wasChanged {
						fmt.Printf("[%s] 🟢 Connected / reconnected to RouteWarden dashboard (%s)\n", time.Now().Format("15:04:05"), dashboardURL)
						select {
						case reconnectSignal <- struct{}{}:
						default:
						}
					}
				} else {
					wasChanged := setConnected(false, nil)
					if wasChanged {
						fmt.Fprintf(os.Stderr, "[%s] 🔴 Disconnected from dashboard (%v). Queuing events offline...\n", time.Now().Format("15:04:05"), res.Err)
					}
				}
			}
		}
	}()

	// Start Batch Flusher with offline queueing
	client := &http.Client{Timeout: 10 * time.Second}
	eventsURL := dashboardURL + "/api/v1/events"

	var buffer []string
	var lastStaleWarnTime time.Time
	totalShipped := 0
	ticker := time.NewTicker(*flushInterval)
	defer ticker.Stop()

	trimStaleEvents := func() {
		conn, lastConn, _ := getConnState()
		if !conn {
			if time.Since(lastConn) > *disconnectTimeout {
				if time.Since(lastStaleWarnTime) >= 30*time.Second {
					lastStaleWarnTime = time.Now()
					fmt.Fprintf(os.Stderr, "[%s] ⚠️ Disconnected for > %v. Dropping stale events to protect memory (queue size: %d)\n",
						time.Now().Format("15:04:05"), *disconnectTimeout, len(buffer))
				}
				if len(buffer) > *batchSize {
					buffer = buffer[len(buffer)-*batchSize:]
				} else {
					buffer = nil
				}
			}
		}
		if len(buffer) > *maxQueueSize {
			drop := len(buffer) - *maxQueueSize
			buffer = buffer[drop:]
		}
	}

	flush := func() {
		if len(buffer) == 0 {
			return
		}

		conn, _, _ := getConnState()
		if !conn {
			trimStaleEvents()
			return
		}

		for len(buffer) > 0 {
			_, _, pk := getConnState()
			n := *batchSize
			if len(buffer) < n {
				n = len(buffer)
			}
			batch := buffer[:n]

			ts := time.Now().Format("15:04:05")
			if err := SendBatchWithRetry(ctx, client, eventsURL, agentToken, agentID, hostname, pk, batch); err != nil {
				errStr := err.Error()
				isAuthErr := strings.Contains(errStr, "401") || strings.Contains(errStr, "403")
				if isAuthErr {
					fmt.Fprintf(os.Stderr, "[%s] ❌ Authentication failed (%v). Dropping batch of %d event(s)\n", ts, err, len(batch))
					buffer = buffer[n:]
					return
				}

				// Connection or server error: mark disconnected, keep batch in buffer
				wasChanged := setConnected(false, nil)
				if wasChanged {
					fmt.Fprintf(os.Stderr, "[%s] 🔴 Disconnected from dashboard (%v). Queuing events offline (current queue: %d)...\n", ts, err, len(buffer))
				}
				trimStaleEvents()
				return
			}

			// Batch sent successfully
			buffer = buffer[n:]
			totalShipped += n
			fmt.Printf("[%s] 📦 Pushed batch of %d event(s) to dashboard (total: %d)\n", ts, n, totalShipped)
			if *verbose {
				for _, ev := range batch {
					fmt.Printf("[%s]    ↳ %s\n", ts, ev)
				}
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
			trimStaleEvents()
			if len(buffer) >= *batchSize {
				conn, _, _ := getConnState()
				if conn {
					flush()
				}
			}

		case <-reconnectSignal:
			if len(buffer) > 0 {
				fmt.Printf("[%s] 🚀 Dashboard reconnected! Flushing %d queued offline event(s)...\n", time.Now().Format("15:04:05"), len(buffer))
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func TailFileToChan(ctx context.Context, path, tailLines string, out chan<- string) {
	TailFileFilteredToChan(ctx, path, tailLines, FilterOptions{AllLogs: true}, out)
}

func TailFileFilteredToChan(ctx context.Context, path, tailLines string, opts FilterOptions, out chan<- string) {
	if tailLines == "" {
		tailLines = "50"
	}
	cmd := exec.CommandContext(ctx, "tail", "-F", "-n", tailLines, path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [File %s] Failed to open pipe: %v; falling back to native file watcher\n", path, err)
		StreamFileFilteredToChan(ctx, path, tailLines, opts, out)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ [File %s] Failed to start tail command: %v; falling back to native file watcher\n", path, err)
		StreamFileFilteredToChan(ctx, path, tailLines, opts, out)
		return
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		raw := scanner.Text()
		clean, ok := FilterRouteWardenLogOpts(raw, opts)
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return
		case out <- clean:
		}
	}
	waitErr := cmd.Wait()
	if ctx.Err() == nil {
		if scanErr := scanner.Err(); scanErr != nil {
			fmt.Fprintf(os.Stderr, "⚠️ [File %s] Scanner error: %v; switching to native file watcher\n", path, scanErr)
		} else if waitErr != nil {
			fmt.Fprintf(os.Stderr, "⚠️ [File %s] tail command stopped (%v); switching to native file watcher\n", path, waitErr)
		}
		StreamFileFilteredToChan(ctx, path, "0", opts, out)
	}
}

func StreamFileToChan(ctx context.Context, path, tailLines string, out chan<- string) {
	StreamFileFilteredToChan(ctx, path, tailLines, FilterOptions{AllLogs: true}, out)
}

func StreamFileFilteredToChan(ctx context.Context, path, tailLines string, opts FilterOptions, out chan<- string) {
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
				if clean, ok := FilterRouteWardenLogOpts(scanner.Text(), opts); ok {
					initialLines = append(initialLines, clean)
				}
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
				if clean, ok := FilterRouteWardenLogOpts(line, opts); ok {
					select {
					case <-ctx.Done():
						return
					case out <- clean:
					}
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
							if clean, ok := FilterRouteWardenLogOpts(trimmed, opts); ok {
								select {
								case <-ctx.Done():
									return
								case out <- clean:
								}
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

// StatusRange represents an inclusive HTTP status code range [Min, Max].
type StatusRange struct {
	Min int
	Max int
}

// StatusCodeFilter matches HTTP status codes against a list of StatusRanges.
type StatusCodeFilter []StatusRange

func (f StatusCodeFilter) Matches(status int) bool {
	for _, r := range f {
		if status >= r.Min && status <= r.Max {
			return true
		}
	}
	return false
}

func (f StatusCodeFilter) String() string {
	if len(f) == 0 {
		return ""
	}
	var parts []string
	for _, r := range f {
		if r.Min == r.Max {
			parts = append(parts, strconv.Itoa(r.Min))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Min, r.Max))
		}
	}
	return strings.Join(parts, ", ")
}

// ParseStatusCodeFilter parses a comma-separated list of status codes or ranges.
// Examples: "400-599", "301", "404, 500-504", "4xx, 5xx", "4XX".
func ParseStatusCodeFilter(expr string) StatusCodeFilter {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	var filter StatusCodeFilter
	parts := strings.Split(expr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		if len(lower) == 3 && strings.HasSuffix(lower, "xx") && lower[0] >= '1' && lower[0] <= '5' {
			hundred := int(lower[0]-'0') * 100
			filter = append(filter, StatusRange{Min: hundred, Max: hundred + 99})
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			minStr := strings.TrimSpace(rangeParts[0])
			maxStr := strings.TrimSpace(rangeParts[1])
			min, errMin := strconv.Atoi(minStr)
			max, errMax := strconv.Atoi(maxStr)
			if errMin == nil && errMax == nil && min <= max && min >= 100 && max <= 999 {
				filter = append(filter, StatusRange{Min: min, Max: max})
			}
			continue
		}
		if code, err := strconv.Atoi(part); err == nil && code >= 100 && code <= 999 {
			filter = append(filter, StatusRange{Min: code, Max: code})
		}
	}
	return filter
}

// FilterOptions controls which lines are forwarded by the remote shipper.
type FilterOptions struct {
	StatusCodes   StatusCodeFilter // Match HTTP requests matching specific status codes or ranges (e.g. 400-599, 301, 4xx, 5xx)
	IncludeFailed bool             // Legacy fallback: if true and StatusCodes is empty, treats as 400-599
	AllTraffic    bool             // If true, include all HTTP traffic (both successful 2xx/3xx and failed 4xx/5xx)
	AllLogs       bool             // If true, ship all raw container lines without filtering
}

// CombinedLogRegex matches standard Common / Combined Apache and NGINX access log lines:
// e.g. 198.51.100.1 - - [20/Oct/2026:14:00:01 +0000] "GET /api HTTP/1.1" 200 123 "-" "..."
var CombinedLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+\S+`)

// DockerTimestampPrefixRegex matches Docker's optional leading timestamp (UTC or timezone offset):
// e.g. "2026-10-20T14:00:01.123456789Z " or "2026-10-20T14:00:01.123456789+00:00 "
var DockerTimestampPrefixRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+`)

type flexibleInt int

func (fi *flexibleInt) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = strings.Trim(s, `"`)
		if n, err := strconv.Atoi(s); err == nil {
			*fi = flexibleInt(n)
		}
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*fi = flexibleInt(n)
	}
	return nil
}

type RouteWardenCheck struct {
	ClientIP       string      `json:"client_ip"`
	ClientIPAlt    string      `json:"ip"`
	ClientHost     string      `json:"ClientHost"`
	RemoteAddr     string      `json:"remote_addr"`
	RemoteIP       string      `json:"remote_ip"`
	Verdict        string      `json:"verdict"`
	Action         string      `json:"action"`
	Method         string      `json:"method"`
	RequestMethod  string      `json:"RequestMethod"`
	Path           string      `json:"path"`
	PathAlt        string      `json:"request_uri"`
	RequestPath    string      `json:"RequestPath"`
	URI            string      `json:"uri"`
	MatchedPattern string      `json:"matched_pattern"`
	Rule           string      `json:"rule"`
	StatusCode     flexibleInt `json:"status"`
	StatusCodeAlt  flexibleInt `json:"status_code"`
	DownstreamStat flexibleInt `json:"DownstreamStatus"`
	Plugin         string      `json:"plugin"`
	Gateway        string      `json:"gateway"`
	Logger         string      `json:"logger"`
	Request        *struct {
		ClientIP   string `json:"client_ip"`
		RemoteIP   string `json:"remote_ip"`
		RemoteAddr string `json:"remote_addr"`
		URI        string `json:"uri"`
		Method     string `json:"method"`
		Host       string `json:"host"`
	} `json:"request"`
}

// isSecurityEvent checks if a line has explicit Routewarden security signals or security status codes (403, 429).
func isSecurityEvent(line string, ev *RouteWardenCheck) bool {
	if ev != nil {
		if ev.Verdict != "" || ev.Action != "" {
			return true
		}
		if ev.Rule != "" || ev.MatchedPattern != "" {
			return true
		}
		if ev.Plugin != "" || ev.Gateway != "" {
			return true
		}
		st := ev.StatusCode
		if st == 0 {
			st = ev.StatusCodeAlt
		}
		if st == 0 {
			st = ev.DownstreamStat
		}
		if st == 403 || st == 429 {
			return true
		}
	}
	// Common / Combined log with RouteWarden indicators: [BLOCK: ...], [TARPIT: ...], [RULE: ...], etc.
	if strings.Contains(line, "[BLOCK") || strings.Contains(line, "[TARPIT") ||
		strings.Contains(line, "[RULE") || strings.Contains(line, "[HONEYPOT") ||
		strings.Contains(line, "[ALLOW") || strings.Contains(line, "RouteWarden") ||
		strings.Contains(line, "Routewarden") {
		return true
	}
	// Check Combined / Common Log format for status 403 or 429
	if match := CombinedLogRegex.FindStringSubmatch(line); len(match) >= 6 {
		if match[5] == "403" || match[5] == "429" {
			return true
		}
	}
	return false
}

// extractHTTPStatus parses the HTTP status code and verifies if line is an HTTP access event.
func extractHTTPStatus(line string, ev *RouteWardenCheck) (status int, isHTTP bool) {
	if ev != nil {
		if ev.Request != nil {
			if ev.ClientIP == "" {
				ev.ClientIP = ev.Request.ClientIP
			}
			if ev.ClientIP == "" {
				ev.ClientIP = ev.Request.RemoteIP
			}
			if ev.ClientIP == "" {
				ev.ClientIP = ev.Request.RemoteAddr
			}
			if ev.Path == "" {
				ev.Path = ev.Request.URI
			}
			if ev.Method == "" {
				ev.Method = ev.Request.Method
			}
		}
		if ev.ClientIP == "" {
			ev.ClientIP = ev.RemoteAddr
		}
		if ev.ClientIP == "" {
			ev.ClientIP = ev.RemoteIP
		}
		if ev.Path == "" {
			ev.Path = ev.URI
		}

		hasIP := ev.ClientIP != "" || ev.ClientIPAlt != "" || ev.ClientHost != ""
		hasPath := ev.Path != "" || ev.PathAlt != "" || ev.RequestPath != ""
		hasMethod := ev.Method != "" || ev.RequestMethod != ""
		st := ev.StatusCode
		if st == 0 {
			st = ev.StatusCodeAlt
		}
		if st == 0 {
			st = ev.DownstreamStat
		}

		if (hasIP && (hasPath || hasMethod || st > 0)) || (hasPath && hasMethod) || ev.Logger == "http.log.access" || strings.HasPrefix(ev.Logger, "http.log.access") {
			return int(st), true
		}
	}

	// Check Combined / Common Log format
	if match := CombinedLogRegex.FindStringSubmatch(line); len(match) >= 6 {
		st, err := strconv.Atoi(match[5])
		if err == nil {
			return st, true
		}
		return 0, true
	}

	return 0, false
}

// IsRouteWardenLog returns true if line is a valid RouteWarden security event.
func IsRouteWardenLog(line string) bool {
	return IsRouteWardenLogOpts(line, FilterOptions{})
}

// IsRouteWardenLogOpts returns true if line matches the active FilterOptions.
func IsRouteWardenLogOpts(line string, opts FilterOptions) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if opts.AllLogs {
		return true
	}

	var ev *RouteWardenCheck
	if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
		var check RouteWardenCheck
		if err := json.Unmarshal([]byte(line), &check); err == nil {
			ev = &check
		}
	}

	// 1. Always accept explicit security enforcement events & threat rule detections
	if isSecurityEvent(line, ev) {
		return true
	}

	// 2. Check if this is an HTTP request log
	status, isHTTP := extractHTTPStatus(line, ev)
	if isHTTP {
		if opts.AllTraffic {
			return true
		}
		if len(opts.StatusCodes) > 0 {
			if opts.StatusCodes.Matches(status) {
				return true
			}
		} else if opts.IncludeFailed && status >= 400 {
			return true
		}
	}

	return false
}

// FilterRouteWardenLog sanitizes a container log line and checks if it should be shipped (backward compatible).
func FilterRouteWardenLog(line string, allLogs bool) (string, bool) {
	return FilterRouteWardenLogOpts(line, FilterOptions{AllLogs: allLogs})
}

// FilterRouteWardenLogOpts sanitizes a container log line and checks if it should be shipped based on options.
func FilterRouteWardenLogOpts(line string, opts FilterOptions) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	if opts.AllLogs {
		return line, true
	}
	cleanLine := line
	if loc := DockerTimestampPrefixRegex.FindStringIndex(line); loc != nil && loc[0] == 0 {
		cleanLine = strings.TrimSpace(line[loc[1]:])
	}
	if IsRouteWardenLogOpts(cleanLine, opts) {
		return cleanLine, true
	}
	return "", false
}

// TailContainerToChan tails a container with RouteWarden log filtering enabled by default.
func TailContainerToChan(ctx context.Context, containerName, tailLines string, out chan<- string) {
	TailContainerWithFilterOptsToChan(ctx, containerName, tailLines, FilterOptions{}, out)
}

// TailContainerFilteredToChan tails a container, optionally bypassing RouteWarden filtering if allLogs is true.
func TailContainerFilteredToChan(ctx context.Context, containerName, tailLines string, allLogs bool, out chan<- string) {
	TailContainerWithFilterOptsToChan(ctx, containerName, tailLines, FilterOptions{AllLogs: allLogs}, out)
}

// TailContainerWithFilterOptsToChan tails a container with configurable FilterOptions.
func TailContainerWithFilterOptsToChan(ctx context.Context, containerName, tailLines string, opts FilterOptions, out chan<- string) {
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
			cleanText, ok := FilterRouteWardenLogOpts(rawText, opts)
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

// WatchDockerContainersToChan watches discovered containers with RouteWarden filtering enabled.
func WatchDockerContainersToChan(ctx context.Context, customLabel, tailLines string, out chan<- string) {
	WatchDockerContainersWithFilterOptsToChan(ctx, customLabel, tailLines, FilterOptions{}, out)
}

// WatchDockerContainersFilteredToChan watches discovered containers with configurable allLogs filtering.
func WatchDockerContainersFilteredToChan(ctx context.Context, customLabel, tailLines string, allLogs bool, out chan<- string) {
	WatchDockerContainersWithFilterOptsToChan(ctx, customLabel, tailLines, FilterOptions{AllLogs: allLogs}, out)
}

// WatchDockerContainersWithFilterOptsToChan watches discovered containers with configurable FilterOptions.
func WatchDockerContainersWithFilterOptsToChan(ctx context.Context, customLabel, tailLines string, opts FilterOptions, out chan<- string) {
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

		fmt.Printf("🐳 [Docker] Attached to container: %s (%s)\n", name, id[:minLen(12, len(id))])

		go func() {
			defer func() {
				mu.Lock()
				delete(active, id)
				mu.Unlock()
				if ctx.Err() == nil {
					fmt.Printf("🛑 [Docker] Container stopped: %s (%s)\n", name, id[:minLen(12, len(id))])
				}
			}()

			TailContainerWithFilterOptsToChan(cCtx, id, tailLines, opts, out)
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

type PingResult struct {
	Connected       bool
	ServerPubKey    *ecdh.PublicKey
	ServerPubKeyStr string
	StatusCode      int
	Err             error
}

var (
	pushKeyUpdateMu       sync.Mutex
	pushOnKeyUpdatedFuncs []func(*ecdh.PublicKey)
)

func RegisterKeyUpdateCallback(cb func(*ecdh.PublicKey)) {
	pushKeyUpdateMu.Lock()
	defer pushKeyUpdateMu.Unlock()
	pushOnKeyUpdatedFuncs = append(pushOnKeyUpdatedFuncs, cb)
}

func NotifyKeyUpdated(pk *ecdh.PublicKey) {
	if pk == nil {
		return
	}
	pushKeyUpdateMu.Lock()
	defer pushKeyUpdateMu.Unlock()
	for _, cb := range pushOnKeyUpdatedFuncs {
		cb(pk)
	}
}

func PingDashboard(ctx context.Context, client *http.Client, dashboardURL, agentToken, hostname string) PingResult {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	url := strings.TrimRight(dashboardURL, "/") + "/api/v1/ping"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PingResult{Connected: false, Err: err}
	}
	if agentToken != "" {
		req.Header.Set("Authorization", "Bearer "+agentToken)
	}
	if hostname != "" {
		req.Header.Set("X-Agent-Hostname", hostname)
	}

	resp, err := client.Do(req)
	if err != nil {
		return PingResult{Connected: false, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Fallback to /api/v1/pubkey for older dashboards
		pk := FetchServerPubKey(dashboardURL)
		return PingResult{
			Connected:    true,
			ServerPubKey: pk,
			StatusCode:   resp.StatusCode,
		}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return PingResult{
			Connected:  false,
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("authentication failed (HTTP %d)", resp.StatusCode),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return PingResult{
			Connected:  false,
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("unexpected status code: %d", resp.StatusCode),
		}
	}

	var res struct {
		Status    string `json:"status"`
		PublicKey string `json:"public_key"`
		Version   string `json:"version"`
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return PingResult{Connected: false, Err: err}
	}
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return PingResult{Connected: false, Err: err}
	}

	var pk *ecdh.PublicKey
	if res.PublicKey != "" {
		if decoded, err := crypto.DecodePublicKey(res.PublicKey); err == nil {
			pk = decoded
			NotifyKeyUpdated(pk)
		}
	}

	return PingResult{
		Connected:       true,
		ServerPubKey:    pk,
		ServerPubKeyStr: res.PublicKey,
		StatusCode:      resp.StatusCode,
	}
}

func SendBatchWithRetry(ctx context.Context, client *http.Client, eventsURL, agentToken, agentID, hostname string, serverPubKey *ecdh.PublicKey, batch []string) error {
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

	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	currentKey := serverPubKey
	buildBody := func(pk *ecdh.PublicKey) []byte {
		if pk != nil {
			encrypted, err := crypto.Encrypt(pk, payloadBytes)
			if err == nil {
				if encBytes, err := json.Marshal(encrypted); err == nil {
					return encBytes
				}
			}
		}
		return payloadBytes
	}

	bodyToSend := buildBody(currentKey)

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
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
				return nil
			}

			// If server returned 400 Bad Request (e.g. decryption failed because server restarted with a new key)
			if resp.StatusCode == http.StatusBadRequest {
				var errResp struct {
					Error     string `json:"error"`
					PublicKey string `json:"public_key"`
				}
				if json.Unmarshal(respBody, &errResp) == nil && errResp.PublicKey != "" {
					if newPk, decErr := crypto.DecodePublicKey(errResp.PublicKey); decErr == nil {
						// Dashboard rotated/reloaded key on restart! Update currentKey and re-encrypt
						currentKey = newPk
						NotifyKeyUpdated(newPk)
						bodyToSend = buildBody(currentKey)
						continue
					}
				}
			}

			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return lastErr
			}
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

func ResolveFileList(flags []string, positionalArgs []string) []string {
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

func ResolveContainerList(flags []string) []string {
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

func minLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func FetchServerPubKey(dashboardURL string) *ecdh.PublicKey {
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

var fetchServerPubKey = FetchServerPubKey
