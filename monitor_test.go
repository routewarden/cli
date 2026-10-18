package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogEvent_Getters(t *testing.T) {
	t.Run("getIP fallback", func(t *testing.T) {
		ev1 := &logEvent{ClientIP: "192.168.1.10"}
		if ev1.getIP() != "192.168.1.10" {
			t.Errorf("expected 192.168.1.10, got %s", ev1.getIP())
		}

		ev2 := &logEvent{ClientIPAlt: "10.0.0.5"}
		if ev2.getIP() != "10.0.0.5" {
			t.Errorf("expected 10.0.0.5, got %s", ev2.getIP())
		}

		ev3 := &logEvent{}
		if ev3.getIP() != "-" {
			t.Errorf("expected '-', got %s", ev3.getIP())
		}
	})

	t.Run("getPath fallback", func(t *testing.T) {
		ev1 := &logEvent{Path: "/api/v1/users"}
		if ev1.getPath() != "/api/v1/users" {
			t.Errorf("expected /api/v1/users, got %s", ev1.getPath())
		}

		ev2 := &logEvent{PathAlt: "/.env"}
		if ev2.getPath() != "/.env" {
			t.Errorf("expected /.env, got %s", ev2.getPath())
		}

		ev3 := &logEvent{}
		if ev3.getPath() != "/" {
			t.Errorf("expected '/', got %s", ev3.getPath())
		}
	})

	t.Run("getVerdict fallback", func(t *testing.T) {
		ev1 := &logEvent{Verdict: "block"}
		if ev1.getVerdict() != "BLOCK" {
			t.Errorf("expected BLOCK, got %s", ev1.getVerdict())
		}

		ev2 := &logEvent{StatusCode: 403}
		if ev2.getVerdict() != "BLOCK" {
			t.Errorf("expected BLOCK for 403, got %s", ev2.getVerdict())
		}

		ev3 := &logEvent{StatusCodeAlt: 429}
		if ev3.getVerdict() != "TARPIT" {
			t.Errorf("expected TARPIT for 429, got %s", ev3.getVerdict())
		}

		ev4 := &logEvent{StatusCode: 200}
		if ev4.getVerdict() != "ALLOW" {
			t.Errorf("expected ALLOW for 200, got %s", ev4.getVerdict())
		}
	})

	t.Run("getPattern fallback", func(t *testing.T) {
		ev1 := &logEvent{MatchedPattern: "*.env"}
		if ev1.getPattern() != "*.env" {
			t.Errorf("expected *.env, got %s", ev1.getPattern())
		}

		ev2 := &logEvent{MatchedRuleAlt: "traversal_detected"}
		if ev2.getPattern() != "traversal_detected" {
			t.Errorf("expected traversal_detected, got %s", ev2.getPattern())
		}

		ev3 := &logEvent{}
		if ev3.getPattern() != "" {
			t.Errorf("expected empty string, got %s", ev3.getPattern())
		}
	})

	t.Run("getLatency fallback", func(t *testing.T) {
		ev1 := &logEvent{LatencyMs: 1.45}
		if ev1.getLatency() != 1.45 {
			t.Errorf("expected 1.45, got %f", ev1.getLatency())
		}

		ev2 := &logEvent{DurationMsAlt: 3.12}
		if ev2.getLatency() != 3.12 {
			t.Errorf("expected 3.12, got %f", ev2.getLatency())
		}

		ev3 := &logEvent{}
		if ev3.getLatency() != 0 {
			t.Errorf("expected 0, got %f", ev3.getLatency())
		}
	})
}

func TestLogEvent_ToCombinedLog(t *testing.T) {
	t.Run("fully populated event", func(t *testing.T) {
		ev := &logEvent{
			Timestamp:      "2026-10-18T12:00:00Z",
			ClientIP:       "203.0.113.195",
			Method:         "POST",
			Path:           "/.env",
			StatusCode:     403,
			MatchedPattern: "dotenv_probe",
		}
		combined := ev.toCombinedLog()
		if !strings.Contains(combined, "203.0.113.195") {
			t.Errorf("missing IP in: %s", combined)
		}
		if !strings.Contains(combined, `"POST /.env HTTP/1.1" 403`) {
			t.Errorf("missing request line in: %s", combined)
		}
		if !strings.Contains(combined, `"dotenv_probe"`) {
			t.Errorf("missing rule in: %s", combined)
		}
		if !combinedLogRegex.MatchString(combined) {
			t.Errorf("combined log line did not match combinedLogRegex: %s", combined)
		}
	})

	t.Run("empty event with fallbacks", func(t *testing.T) {
		ev := &logEvent{
			Verdict: "TARPIT",
		}
		combined := ev.toCombinedLog()
		if !strings.Contains(combined, "127.0.0.1") {
			t.Errorf("expected fallback IP 127.0.0.1, got: %s", combined)
		}
		if !strings.Contains(combined, `"GET / HTTP/1.1" 429`) {
			t.Errorf("expected fallback GET / 429, got: %s", combined)
		}
		if !strings.Contains(combined, `"RouteWarden"`) {
			t.Errorf("expected default rule RouteWarden, got: %s", combined)
		}
		if !combinedLogRegex.MatchString(combined) {
			t.Errorf("did not match regex: %s", combined)
		}
	})

	t.Run("alt timestamp parsing", func(t *testing.T) {
		ev := &logEvent{
			TimestampAlt: "2026-05-01T15:30:00Z",
			ClientIP:     "10.0.0.1",
			Path:         "/health",
			StatusCode:   200,
		}
		combined := ev.toCombinedLog()
		if !strings.Contains(combined, "01/May/2026:15:30:00") {
			t.Errorf("expected parsed May timestamp, got: %s", combined)
		}
	})
}

func TestParseLogLine(t *testing.T) {
	t.Run("valid standard JSON", func(t *testing.T) {
		line := `{"time":"2026-10-18T10:00:00Z","client_ip":"1.2.3.4","verdict":"BLOCK","method":"GET","path":"/admin","matched_pattern":"admin_block","status":403,"latency_ms":0.5}`
		ev := parseLogLine(line)
		if ev == nil {
			t.Fatalf("expected non-nil logEvent")
		}
		if ev.ClientIP != "1.2.3.4" || ev.Verdict != "BLOCK" || ev.StatusCode != 403 {
			t.Errorf("parsed event mismatch: %+v", ev)
		}
	})

	t.Run("valid alt-keys JSON", func(t *testing.T) {
		line := `{"timestamp":"2026-10-18T10:00:00Z","ip":"5.6.7.8","request_uri":"/secret.bak","rule":"bak_file","status_code":429,"duration_ms":1.2}`
		ev := parseLogLine(line)
		if ev == nil {
			t.Fatalf("expected non-nil logEvent")
		}
		if ev.getIP() != "5.6.7.8" || ev.getPath() != "/secret.bak" || ev.getVerdict() != "TARPIT" {
			t.Errorf("parsed event getters mismatch: ip=%s path=%s verdict=%s", ev.getIP(), ev.getPath(), ev.getVerdict())
		}
	})

	t.Run("valid Combined log format", func(t *testing.T) {
		line := `198.51.100.42 - - [18/Oct/2026:14:22:01 +0000] "GET /phpmyadmin HTTP/1.1" 403 145 "-" "curl/7.68.0"`
		ev := parseLogLine(line)
		if ev == nil {
			t.Fatalf("expected non-nil logEvent from combined log")
		}
		if ev.ClientIP != "198.51.100.42" {
			t.Errorf("expected 198.51.100.42, got %s", ev.ClientIP)
		}
		if ev.Method != "GET" || ev.Path != "/phpmyadmin" || ev.StatusCode != 403 {
			t.Errorf("mismatch in parsed combined line: %+v", ev)
		}
	})

	t.Run("malformed line", func(t *testing.T) {
		line := `invalid log entry that is neither JSON nor combined format`
		ev := parseLogLine(line)
		if ev != nil {
			t.Errorf("expected nil for non-matching line, got: %+v", ev)
		}
	})

	t.Run("corrupt JSON", func(t *testing.T) {
		line := `{"client_ip": "1.1.1.1", "status": `
		ev := parseLogLine(line)
		if ev != nil {
			t.Errorf("expected nil for corrupt JSON, got: %+v", ev)
		}
	})
}

func TestProcessLogStream_FiltersAndOutput(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "monitored.log")

	msgChan := make(chan streamMsg, 10)
	msgChan <- streamMsg{Container: "nginx-ingress", Line: `{"time":"2026-10-18T10:00:00Z","client_ip":"192.168.1.100","verdict":"BLOCK","method":"GET","path":"/.env","matched_pattern":"dotenv","status":403}`}
	msgChan <- streamMsg{Container: "nginx-ingress", Line: `{"time":"2026-10-18T10:00:01Z","client_ip":"192.168.1.101","verdict":"ALLOW","method":"GET","path":"/index.html","status":200}`}
	msgChan <- streamMsg{Container: "traefik", Line: `{"time":"2026-10-18T10:00:02Z","client_ip":"10.0.0.50","verdict":"TARPIT","method":"POST","path":"/wp-login.php","matched_pattern":"wp_tarpit","status":429}`}
	msgChan <- streamMsg{Container: "traefik", Line: `unstructured log banner line`}
	close(msgChan)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	processLogStream(msgChan, "", "", "", outPath, false)

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	stdout := buf.String()

	// Verify formatted output
	if !strings.Contains(stdout, "🛑 BLOCK") {
		t.Errorf("expected BLOCK badge in stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "🛡️ ALLOW") {
		t.Errorf("expected ALLOW badge in stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "⏳ TARPIT") {
		t.Errorf("expected TARPIT badge in stdout: %s", stdout)
	}
	if !strings.Contains(stdout, "[nginx-ingress]") || !strings.Contains(stdout, "[traefik]") {
		t.Errorf("expected container labels in stdout: %s", stdout)
	}

	// Verify written outPath file
	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read outPath: %v", err)
	}
	outStr := string(outData)
	if !strings.Contains(outStr, "192.168.1.100") || !strings.Contains(outStr, "/.env") {
		t.Errorf("expected block event in out file: %s", outStr)
	}
	if !strings.Contains(outStr, "unstructured log banner line") {
		t.Errorf("expected unstructured line in out file: %s", outStr)
	}
}

func TestProcessLogStream_VerdictFilter(t *testing.T) {
	msgChan := make(chan streamMsg, 5)
	msgChan <- streamMsg{Line: `{"client_ip":"1.1.1.1","verdict":"BLOCK","path":"/.env","status":403}`}
	msgChan <- streamMsg{Line: `{"client_ip":"2.2.2.2","verdict":"ALLOW","path":"/home","status":200}`}
	msgChan <- streamMsg{Line: `{"client_ip":"3.3.3.3","verdict":"TARPIT","path":"/admin","status":429}`}
	close(msgChan)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Filter only BLOCK
	processLogStream(msgChan, "BLOCK", "", "", "", false)

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	stdout := buf.String()

	if !strings.Contains(stdout, "1.1.1.1") {
		t.Errorf("expected 1.1.1.1 in filtered output: %s", stdout)
	}
	if strings.Contains(stdout, "2.2.2.2") || strings.Contains(stdout, "3.3.3.3") {
		t.Errorf("non-BLOCK events should have been filtered out: %s", stdout)
	}
}

func TestProcessLogStream_IPAndPathFilters(t *testing.T) {
	msgChan := make(chan streamMsg, 5)
	msgChan <- streamMsg{Line: `{"client_ip":"192.168.1.50","path":"/sensitive/data","status":403}`}
	msgChan <- streamMsg{Line: `{"client_ip":"10.0.0.1","path":"/sensitive/data","status":403}`}
	msgChan <- streamMsg{Line: `{"client_ip":"192.168.1.50","path":"/public/asset.js","status":200}`}
	close(msgChan)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Filter IP substring "192.168" AND path substring "/sensitive"
	processLogStream(msgChan, "", "192.168", "/sensitive", "", false)

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	stdout := buf.String()

	if !strings.Contains(stdout, "192.168.1.50") || !strings.Contains(stdout, "/sensitive/data") {
		t.Errorf("expected matching event in stdout: %s", stdout)
	}
	if strings.Contains(stdout, "10.0.0.1") || strings.Contains(stdout, "/public/asset.js") {
		t.Errorf("unexpected events survived filters: %s", stdout)
	}
}

func TestProcessLogStream_RawOutput(t *testing.T) {
	msgChan := make(chan streamMsg, 2)
	msgChan <- streamMsg{Line: `{"client_ip":"8.8.8.8","method":"GET","path":"/.git","status":403,"verdict":"BLOCK"}`}
	close(msgChan)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	processLogStream(msgChan, "", "", "", "", true)

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	stdout := buf.String()

	// In raw mode, it should emit standard Combined format line
	if !strings.Contains(stdout, "8.8.8.8") || !strings.Contains(stdout, `"GET /.git HTTP/1.1" 403`) {
		t.Errorf("expected raw combined output line: %s", stdout)
	}
	if strings.Contains(stdout, "🛑 BLOCK") {
		t.Errorf("raw mode should not contain color badges: %s", stdout)
	}
}
