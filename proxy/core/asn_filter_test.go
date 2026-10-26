package core

import (
	"context"
	"github.com/routewarden/cli/proxy/config"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func asnTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "asn.json")
	if err := os.WriteFile(path, []byte(`{"AS64500":["8.0.0.0/8","2001:db8::/32"],"64501":["8.8.8.0/24","2001:db8:1::/48"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestASNLongestPrefix(t *testing.T) {
	f, err := NewASNFilter([]string{"as64500"}, asnTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"8.1.2.3", true}, {"8.1.2.3:443", true}, {"::ffff:8.1.2.3", true},
		{"8.8.8.8", false}, {"2001:db8:2::1", true}, {"2001:db8:1::1", false},
		{"9.1.2.3", false}, {"127.0.0.1", false}, {"bad", false}, {"", false},
	} {
		if got := f.IsAllowed(tc.ip); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.ip, got, tc.want)
		}
	}
}
func TestASNValidation(t *testing.T) {
	path := asnTestDB(t)
	for _, allowed := range [][]string{{"0"}, {"4294967296"}, {"AS"}, {"-1"}, {"+64500"}, {"1.2"}, {"64502"}} {
		if _, err := NewASNFilter(allowed, path); err == nil {
			t.Errorf("accepted %v", allowed)
		}
	}
	if _, err := NewASNFilter([]string{"64500"}, ""); err == nil {
		t.Error("accepted missing DB path")
	}
	if _, err := NewASNFilter([]string{"64500"}, path+"missing"); err == nil {
		t.Error("accepted unreadable DB")
	}
	for _, content := range []string{`bad`, `null`, `{}`, `{"64500":["invalid"]}`, `{"64500":["8.0.0.0/8"],"64501":["8.1.0.0/8"]}`} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewASNFilter([]string{"64500"}, path); err == nil {
			t.Errorf("accepted bad database %s", content)
		}
	}
	f, err := NewASNFilter(nil, "nonexistent")
	if err != nil || f.IsAllowed("8.1.2.3") {
		t.Error("disabled feature changed behavior")
	}
}

func TestASNTCPServiceOverride(t *testing.T) {
	f, err := NewASNFilter([]string{"64500", "64501"}, asnTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Global: config.GlobalConfig{AllowedASNs: []string{"64500"}}}
	p := &Pipeline{cfg: cfg, asn: f}
	svc := &config.ServiceConfig{}
	if p.isASNDenied("8.1.2.3", svc) || !p.isASNDenied("8.8.8.8", svc) || !p.isASNDenied("127.0.0.1", svc) {
		t.Error("global ASN restriction failed")
	}
	svc.AllowedASNs = []string{"64501"}
	if !p.isASNDenied("8.1.2.3", svc) || p.isASNDenied("8.8.8.8", svc) {
		t.Error("service override failed")
	}
	p.asn = nil
	if !p.isASNDenied("8.8.8.8", svc) {
		t.Error("missing resolver failed open")
	}
	svc.AllowedASNs = nil
	cfg.Global.AllowedASNs = nil
	if p.isASNDenied("8.8.8.8", svc) {
		t.Error("empty rules should not restrict")
	}
}

func TestASNEnforcedOnTCPAndUDP(t *testing.T) {
	f, err := NewASNFilter([]string{"64500"}, asnTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Global: config.GlobalConfig{AllowedASNs: []string{"64500"}}}
	bl := NewBanList("")
	defer bl.Close()
	stats := NewStatsRegistry()
	bus := NewEventBus()
	defer bus.Close()
	events, unsubscribe := bus.Subscribe(4)
	defer unsubscribe()
	pipe := NewPipeline(cfg, bl, NewFailureTracker(), NewRateLimiter(), bus, stats, nil, nil)
	pipe.asn = f
	svc := config.ServiceConfig{Name: "asn-test", Protocol: "tcp", Response: config.ResponseConfig{Mode: "drop"}}
	client, server := net.Pipe()
	defer client.Close()
	pipe.Handle(context.Background(), &mockAddrConn{Conn: server, remoteIP: "8.8.8.8"}, &svc)
	table := NewUDPSessionTable(time.Second)
	defer table.Close()
	d := &Daemon{cfg: cfg, banlist: bl, stats: stats, bus: bus, pipeline: pipe}
	d.handleUDPPacket(context.Background(), nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1234}, []byte("ping"), svc, table)
	for i := 0; i < 2; i++ {
		select {
		case event := <-events:
			if event.Reason != "asn_denied" || event.Action != "blocked" {
				t.Errorf("unexpected event: %+v", event)
			}
		case <-time.After(time.Second):
			t.Fatal("missing ASN rejection event")
		}
	}
	if table.Len() != 0 {
		t.Error("denied UDP client allocated a session")
	}
}
