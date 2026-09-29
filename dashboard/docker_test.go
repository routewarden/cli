package dashboard

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSecurityEventLine(t *testing.T) {
	line := `{"action":"json","client_ip":"192.168.65.1","method":"GET","path":"/.git/config","pattern":"(?i)(^|/)\\.(git|svn|hg|bzr|cvs)(/.*|$)","plugin":"warden-8080@file","reason":"path_blocked","request_uri":"/.git/config","timestamp":"2026-09-25T04:19:31Z","type":"routewarden_block","user_agent":"curl/8.7.1"}`

	event, ok := parseSecurityEventLine(line, "routewarden-traefik-sample", "5a09e1ab29ec", "traefik-warden")
	if !ok {
		t.Fatalf("expected parseSecurityEventLine to return true, got false")
	}
	if event.ClientIP != "192.168.65.1" {
		t.Errorf("expected client_ip 192.168.65.1, got %s", event.ClientIP)
	}
	if event.Path != "/.git/config" {
		t.Errorf("expected path /.git/config, got %s", event.Path)
	}
	if event.ResponseMode != "json" {
		t.Errorf("expected response_mode json, got %s", event.ResponseMode)
	}
	if !strings.Contains(event.Plugin, "traefik") {
		t.Errorf("expected plugin traefik-warden, got %s", event.Plugin)
	}
}

func TestParseLogStreamMultiplexed(t *testing.T) {
	jsonPayload := `{"action":"json","client_ip":"192.168.65.1","method":"GET","path":"/.git/config","pattern":"(?i)(^|/)\\.(git|svn|hg|bzr|cvs)(/.*|$)","plugin":"warden-8080@file","reason":"path_blocked","request_uri":"/.git/config","timestamp":"2026-09-25T04:19:31Z","type":"routewarden_block","user_agent":"curl/8.7.1"}` + "\n"

	// Construct Docker 8-byte multiplexed header: 0x01 (stdout) + 3 zero bytes + 4 bytes size
	header := make([]byte, 8)
	header[0] = 0x01
	binary.BigEndian.PutUint32(header[4:], uint32(len(jsonPayload)))
	stream := append(header, []byte(jsonPayload)...)

	var received []SecurityEvent
	err := parseLogStream(strings.NewReader(string(stream)), "traefik", "c123", "traefik-warden", func(e SecurityEvent) {
		received = append(received, e)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	if received[0].Path != "/.git/config" {
		t.Errorf("expected path /.git/config, got %s", received[0].Path)
	}
}

func TestDockerWatcherClearStopped(t *testing.T) {
	hub := NewHub()
	buf := NewRingBuffer(10)
	w := NewDockerWatcher("/fake.sock", buf, hub, 1000)

	// Pre-populate with a live source and two stopped sources
	w.sources["live-1"] = &Source{ID: "live-1", Name: "traefik-live", Status: "live"}
	w.sources["stopped-1"] = &Source{ID: "stopped-1", Name: "traefik-old", Status: "stopped"}
	w.sources["error-1"] = &Source{ID: "error-1", Name: "caddy-crashed", Status: "error"}

	if len(w.SourceList()) != 3 {
		t.Fatalf("expected 3 sources initially, got %d", len(w.SourceList()))
	}

	remaining := w.ClearStopped()
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining source after ClearStopped, got %d", len(remaining))
	}
	if remaining[0].ID != "live-1" {
		t.Errorf("expected live-1 to remain, got %s", remaining[0].ID)
	}
}

func TestFileTailerClearStopped(t *testing.T) {
	hub := NewHub()
	buf := NewRingBuffer(10)
	tailer := NewFileTailer([]string{"*.log"}, buf, hub)

	tailer.sources["/var/log/live.log"] = &Source{ID: "f1", Name: "live.log", Status: "live"}
	tailer.sources["/var/log/old.log"] = &Source{ID: "f2", Name: "old.log", Status: "stopped"}

	remaining := tailer.ClearStopped()
	if len(remaining) != 1 {
		t.Fatalf("expected 1 source, got %d", len(remaining))
	}
	if remaining[0].Name != "live.log" {
		t.Errorf("expected live.log, got %s", remaining[0].Name)
	}
}

func TestIsTCPWardenContainer(t *testing.T) {
	cases := []struct {
		image    string
		names    []string
		expected bool
	}{
		{"routewarden/tcp-warden:latest", []string{"/tcp-warden"}, true},
		{"ghcr.io/routewarden/tcp-warden:v1", []string{"/my-service"}, true},
		{"alpine:latest", []string{"/tcp-warden-app"}, true},
		{"alpine:latest", []string{"/prod-tcp-warden-1"}, true},
		{"traefik:v3.0", []string{"/traefik"}, false},
		{"caddy:2.8", []string{"/caddy_server"}, false},
	}

	for _, tc := range cases {
		c := dockerContainer{
			Image: tc.image,
			Names: tc.names,
		}
		if got := isTCPWardenContainer(c); got != tc.expected {
			t.Errorf("isTCPWardenContainer(%s, %v) = %v; want %v", tc.image, tc.names, got, tc.expected)
		}
	}
}

func TestParseTCPWardenSecurityEvent(t *testing.T) {
	line := `{"type":"security_event","timestamp":"2026-09-29T03:10:26.272954545Z","plugin":"tcp-warden","service":"mysql","protocol":"mysql","client_ip":"192.168.65.1","country_code":"LAN","country_name":"Local Network","flag_emoji":"🏠","action":"blocked","reason":"plugin_unavailable: DISABLED (plugin not found)"}`
	ev, ok := parseSecurityEventLine(line, "tcp-warden", "c456", "tcp-warden")
	if !ok {
		t.Fatalf("expected parseSecurityEventLine to succeed")
	}
	if ev.Service != "mysql" || ev.Protocol != "mysql" {
		t.Fatalf("expected mysql service and protocol, got %s / %s", ev.Service, ev.Protocol)
	}
	if ev.Reason != "plugin_unavailable: DISABLED (plugin not found)" {
		t.Fatalf("unexpected reason: %s", ev.Reason)
	}
	if ev.CountryCode != "LAN" || ev.FlagEmoji != "🏠" {
		t.Fatalf("unexpected country or flag: %s %s", ev.CountryCode, ev.FlagEmoji)
	}
	if ev.EventKind != "tcp" {
		t.Fatalf("expected event kind tcp, got %s", ev.EventKind)
	}
}

func TestFileTailerLiveIngestion(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test-access.log")

	initialLog := `[2026-09-29 20:00:00] INFO Starting gateway
{"type":"routewarden_block","timestamp":"2026-09-29T20:00:01Z","plugin":"caddy-warden","method":"GET","path":"/admin/config","client_ip":"192.168.1.10","action":"blocked","reason":"path_blocked"}
[2026-09-29 20:00:02] INFO Routine healthcheck ok
`
	if err := os.WriteFile(logPath, []byte(initialLog), 0644); err != nil {
		t.Fatalf("failed to write initial log: %v", err)
	}

	buf := NewRingBuffer(50)
	hub := NewHub()
	tailer := NewFileTailer([]string{logPath}, buf, hub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go tailer.Run(ctx)

	// Wait for initial file discovery and parsing
	time.Sleep(350 * time.Millisecond)

	events := buf.Recent(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 initial parsed event, got %d", len(events))
	}
	if events[0].Path != "/admin/config" {
		t.Errorf("expected path /admin/config, got %s", events[0].Path)
	}
	if events[0].Plugin != "caddy-warden" {
		t.Errorf("expected plugin caddy-warden, got %s", events[0].Plugin)
	}

	// Append a new TCP Warden security event
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("failed to open log for append: %v", err)
	}
	tcpEvent := `{"type":"security_event","timestamp":"2026-09-29T20:00:10Z","plugin":"tcp-warden","service":"ssh","protocol":"ssh","client_ip":"10.0.0.99","action":"blocked","reason":"crowdsec_ban"}` + "\n"
	if _, err := f.WriteString(tcpEvent); err != nil {
		t.Fatalf("failed to append tcp event: %v", err)
	}
	_ = f.Close()

	// Wait for tailer polling interval (250ms) to read new line
	time.Sleep(400 * time.Millisecond)

	events = buf.Recent(0)
	if len(events) != 2 {
		t.Fatalf("expected 2 total parsed events after append, got %d", len(events))
	}
	if events[1].Service != "ssh" || events[1].Protocol != "ssh" {
		t.Errorf("expected ssh service/protocol, got %s/%s", events[1].Service, events[1].Protocol)
	}
	if events[1].EventKind != "tcp" {
		t.Errorf("expected event kind tcp, got %s", events[1].EventKind)
	}
	if events[1].Reason != "crowdsec_ban" {
		t.Errorf("expected crowdsec_ban reason, got %s", events[1].Reason)
	}
}


