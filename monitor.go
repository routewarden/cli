package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
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

// Regex for standard Combined Apache/Nginx access log
var combinedLogRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+\S+`)

func handleMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	file := fs.String("file", "", "Log file to read from (default: stdin)")
	fs.StringVar(file, "f", "", "Alias for --file")
	verdictFilter := fs.String("verdict", "", "Filter events by verdict (BLOCK, ALLOW, TARPIT)")
	ipFilter := fs.String("ip", "", "Filter events by client IP substring")
	pathFilter := fs.String("path", "", "Filter events by request path substring")
	_ = parseFlagsLenient(fs, args)

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

	fmt.Printf("📡 RouteWarden Threat Monitor — Streaming security events from %s\n", sourceName)
	if *verdictFilter != "" {
		fmt.Printf("   Filter: Verdict = %s\n", strings.ToUpper(*verdictFilter))
	}
	if *ipFilter != "" {
		fmt.Printf("   Filter: IP contains %q\n", *ipFilter)
	}
	if *pathFilter != "" {
		fmt.Printf("   Filter: Path contains %q\n", *pathFilter)
	}
	fmt.Println("   Press Ctrl+C to stop and view aggregate threat summary.")
	fmt.Println(strings.Repeat("─", 80))

	// Tracking stats
	totalEvents := 0
	blockedEvents := 0
	allowedEvents := 0
	tarpitEvents := 0
	uniqueIPs := make(map[string]bool)
	topPaths := make(map[string]int)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
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

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		ev := parseLogLine(line)
		if ev == nil {
			continue
		}

		verdict := ev.getVerdict()
		ip := ev.getIP()
		path := ev.getPath()

		// Apply filters
		if *verdictFilter != "" && !strings.EqualFold(verdict, *verdictFilter) {
			continue
		}
		if *ipFilter != "" && !strings.Contains(ip, *ipFilter) {
			continue
		}
		if *pathFilter != "" && !strings.Contains(path, *pathFilter) {
			continue
		}

		// Update metrics
		totalEvents++
		uniqueIPs[ip] = true
		topPaths[path]++

		badge := "🛡️ ALLOW "
		switch verdict {
		case "BLOCK":
			badge = "🛑 BLOCK "
			blockedEvents++
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

		extra := ""
		if ev.getPattern() != "" {
			extra += fmt.Sprintf(" [Rule: %s]", ev.getPattern())
		}
		if ev.getLatency() > 0 {
			extra += fmt.Sprintf(" (%.2fms)", ev.getLatency())
		}

		fmt.Printf("[%s] %s %-15s -> %-5s %-32s%s\n", timeStr, badge, ip, method, path, extra)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "Error reading log stream: %v\n", err)
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
