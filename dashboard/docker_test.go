package dashboard

import (
	"encoding/binary"
	"strings"
	"testing"
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
	w := NewDockerWatcher("/fake.sock", buf, hub, "1h")

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

