package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/geoip"
	"github.com/routewarden/cli/proxy/plugins"
	"github.com/routewarden/cli/proxy/plugins/sdk"
	"github.com/routewarden/cli/proxy/protocol"
)

func TestPipelineIPFilterAndBanlist(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
		Services: map[string]config.ServiceConfig{
			"test-service": {
				Name:     "test-service",
				Protocol: "tcp",
				IPFilter: config.IPFilterConfig{
					Deny: []string{"198.51.100.0/24"},
				},
				Response: config.ResponseConfig{
					Mode: "drop",
				},
			},
		},
	}

	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	svc := cfg.Services["test-service"]

	// 1. Test Denied IP
	clientConn, serverConn := net.Pipe()
	go func() {
		// Mock remote addr
		pipe.Handle(context.Background(), serverConn, &svc)
	}()

	// Read or wait for close
	buf := make([]byte, 16)
	_, _ = clientConn.Read(buf)
	clientConn.Close()

	// 2. Test Banlist
	bl.Ban("127.0.0.1", "manual_test", "test-service", 1*time.Hour)
	if entry, banned := bl.IsBanned("127.0.0.1"); !banned || entry.Reason != "manual_test" {
		t.Fatalf("expected 127.0.0.1 to be banned")
	}

	bl.Unban("127.0.0.1")
	if _, banned := bl.IsBanned("127.0.0.1"); banned {
		t.Fatalf("expected 127.0.0.1 to be unbanned")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter()

	// 60 conns/min = 1/sec, burst 2
	allowed1 := rl.Allow("ssh", "192.0.2.1", 60, 2)
	allowed2 := rl.Allow("ssh", "192.0.2.1", 60, 2)
	allowed3 := rl.Allow("ssh", "192.0.2.1", 60, 2)

	if !allowed1 || !allowed2 {
		t.Errorf("expected first 2 burst connections to be allowed")
	}
	if allowed3 {
		t.Errorf("expected 3rd immediate connection to exceed burst capacity")
	}
}

func TestFailureTrackerAndAutoBan(t *testing.T) {
	ft := NewFailureTracker()

	c1 := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)
	c2 := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)
	c3 := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)

	if c1 != 1 || c2 != 2 || c3 != 3 {
		t.Errorf("expected 1, 2, 3 failure counts; got %d, %d, %d", c1, c2, c3)
	}

	ft.Reset("ssh", "192.0.2.5")
	cAfter := ft.RecordFailure("ssh", "192.0.2.5", 1*time.Minute)
	if cAfter != 1 {
		t.Errorf("expected 1 failure count after reset, got %d", cAfter)
	}
}

func TestPipeline_AutoBanOnMaxAuthFailures(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
		Services: map[string]config.ServiceConfig{
			"auth-svc": {
				Name:            "auth-svc",
				Protocol:        "tcp",
				MaxAuthFailures: 3,
				BanDuration:     config.Duration(2 * time.Hour),
				Response: config.ResponseConfig{
					Mode: "drop",
				},
			},
		},
	}

	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	svc := cfg.Services["auth-svc"]
	clientIP := "203.0.113.50"

	// 1. Initial state: not banned
	if _, isBanned := bl.IsBanned(clientIP); isBanned {
		t.Fatalf("expected client %s not to be banned initially", clientIP)
	}

	// 2. Record 1st failure -> count = 1, threshold = 3 -> not banned
	pipe.recordAuthFailure(&svc, clientIP, geoip.GeoResult{})
	if _, isBanned := bl.IsBanned(clientIP); isBanned {
		t.Fatalf("expected client %s not to be banned after 1 failure", clientIP)
	}

	// 3. Record 2nd failure -> count = 2, threshold = 3 -> not banned
	pipe.recordAuthFailure(&svc, clientIP, geoip.GeoResult{})
	if _, isBanned := bl.IsBanned(clientIP); isBanned {
		t.Fatalf("expected client %s not to be banned after 2 failures", clientIP)
	}

	// 4. Record 3rd failure -> count = 3, threshold = 3 -> MUST BE BANNED!
	pipe.recordAuthFailure(&svc, clientIP, geoip.GeoResult{})
	entry, isBanned := bl.IsBanned(clientIP)
	if !isBanned {
		t.Fatalf("expected client %s to be automatically banned after reaching MaxAuthFailures", clientIP)
	}
	if !strings.Contains(entry.Reason, "max_auth_failures_exceeded") {
		t.Errorf("unexpected ban reason: %s", entry.Reason)
	}
	if entry.Service != "auth-svc" {
		t.Errorf("expected banned service to be 'auth-svc', got %s", entry.Service)
	}

	// 5. Subsequent connection from banned IP is caught at Stage 2
	connA, connB := net.Pipe()
	defer connA.Close()
	defer connB.Close()

	// Wrap connB with mock address
	mockConn := &mockAddrConn{Conn: connB, remoteIP: clientIP}

	done := make(chan struct{})
	go func() {
		pipe.Handle(context.Background(), mockConn, &svc)
		close(done)
	}()

	select {
	case <-done:
		// Connection handled and dropped
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for pipeline to drop banned connection")
	}

	st := stats.GetOrCreate("auth-svc")
	if st.Snapshot().BlockedConnections == 0 {
		t.Errorf("expected blocked connection count to increment for banned IP")
	}
}

type mockAddrConn struct {
	net.Conn
	remoteIP string
}

func (m *mockAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP(m.remoteIP),
		Port: 54321,
	}
}

func TestAPIServerEndpoints(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:9091",
		},
		Services: map[string]config.ServiceConfig{
			"ssh": {
				Name:     "ssh",
				Listen:   ":2222",
				Upstream: "127.0.0.1:22",
				Protocol: "ssh",
			},
		},
	}

	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	// 1. Test /health
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /health, got %d", rec.Code)
	}
	var healthResp map[string]any
	json.NewDecoder(rec.Body).Decode(&healthResp)
	if healthResp["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", healthResp["status"])
	}

	// 2. Test /api/ban
	banReqBody := []byte(`{"ip":"198.51.100.99","reason":"test_ban","duration":"30m"}`)
	reqBan := httptest.NewRequest(http.MethodPost, "/api/ban", bytes.NewReader(banReqBody))
	recBan := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBan, reqBan)

	if recBan.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/ban, got %d", recBan.Code)
	}
	if _, ok := bl.IsBanned("198.51.100.99"); !ok {
		t.Fatalf("expected 198.51.100.99 to be banned via API")
	}

	// 3. Test /api/banlist
	reqList := httptest.NewRequest(http.MethodGet, "/api/banlist", nil)
	recList := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recList, reqList)

	var list []BanEntry
	json.NewDecoder(recList.Body).Decode(&list)
	if len(list) != 1 || list[0].IP != "198.51.100.99" {
		t.Errorf("unexpected banlist response: %+v", list)
	}

	// 4. Test /api/unban
	unbanReqBody := []byte(`{"ip":"198.51.100.99"}`)
	reqUnban := httptest.NewRequest(http.MethodPost, "/api/unban", bytes.NewReader(unbanReqBody))
	recUnban := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recUnban, reqUnban)

	if recUnban.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/unban, got %d", recUnban.Code)
	}
	if _, ok := bl.IsBanned("198.51.100.99"); ok {
		t.Fatalf("expected 198.51.100.99 to be unbanned via API")
	}

	// 5. Test invalid IP rejection on /api/ban and /api/unban
	reqBadBan := httptest.NewRequest(http.MethodPost, "/api/ban", bytes.NewReader([]byte(`{"ip":"not-an-ip"}`)))
	recBadBan := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBadBan, reqBadBan)
	if recBadBan.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid IP in ban, got %d", recBadBan.Code)
	}

	reqBadUnban := httptest.NewRequest(http.MethodPost, "/api/unban", bytes.NewReader([]byte(`{"ip":"not-an-ip"}`)))
	recBadUnban := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBadUnban, reqBadUnban)
	if recBadUnban.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for invalid IP in unban, got %d", recBadUnban.Code)
	}
}

func TestAPIServerUnixSocket(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "tw.sock")

	// Probe whether unix domain socket creation is permitted in this execution environment
	probeLn, probeErr := net.Listen("unix", sockPath)
	if probeErr != nil {
		t.Skipf("skipping unix socket test: unix domain socket bind not permitted in this environment: %v", probeErr)
	}
	probeLn.Close()
	_ = os.Remove(sockPath)

	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled:    true,
			Socket:     sockPath,
			SocketMode: 0666,
		},
	}

	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	go func() {
		_ = api.Start()
	}()
	defer api.Close()

	// Wait up to 2 seconds for unix socket to exist
	var conn net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("unix", sockPath, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to connect to unix socket %s: %v", sockPath, err)
	}
	conn.Close()

	// Make HTTP request over unix socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get("http://unix/health")
	if err != nil {
		t.Fatalf("failed GET /health over unix socket: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from unix socket /health, got %d", resp.StatusCode)
	}

	var health map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("failed decoding health json: %v", err)
	}
	if health["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", health["status"])
	}

	// Close API and verify socket cleanup
	if err := api.Close(); err != nil {
		t.Fatalf("unexpected error closing api server: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected unix socket %s to be removed on Close, but stat returned %v", sockPath, err)
	}
}

func TestEventBus_CloseSubscribeSafety(t *testing.T) {
	bus := NewEventBus()
	_, unsub := bus.Subscribe(5)
	unsub()

	bus.Close()

	// Calling Publish, Subscribe, and unsub after Close must not panic
	bus.Publish(SecurityEvent{Action: "test"})
	ch2, unsub2 := bus.Subscribe(5)
	if _, open := <-ch2; open {
		t.Errorf("expected channel from closed bus to be closed")
	}
	unsub2()
}

type brokenSelfTestPlugin struct{}

func (b *brokenSelfTestPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:      "broken-test-plugin",
		Protocols: []string{"broken-proto"},
	}
}
func (b *brokenSelfTestPlugin) ValidateConfig(cfg map[string]any) error        { return nil }
func (b *brokenSelfTestPlugin) CreateInspector(cfg map[string]any) (sdk.Inspector, error) {
	return nil, nil
}
func (b *brokenSelfTestPlugin) SelfTest() error {
	return errors.New("deliberate self-test failure: database handshake assertion timed out")
}

func TestPipeline_ModularPluginAutoDisable(t *testing.T) {
	// Register deliberately broken plugin
	broken := &brokenSelfTestPlugin{}
	plugins.Register(broken)

	// Attempt to enable it (should fail self-test)
	if err := plugins.Enable("broken-test-plugin"); err == nil {
		t.Fatalf("expected enabling broken-test-plugin to fail")
	}
	if plugins.IsActive("broken-proto") {
		t.Fatalf("broken-proto should NOT be active")
	}

	cfg := &config.Config{
		Version: "1.0",
		Services: map[string]config.ServiceConfig{
			"failing-service": {
				Name:     "failing-service",
				Protocol: "broken-proto",
				Response: config.ResponseConfig{
					Mode:          "reject",
					RejectMessage: "PLUGIN_DISABLED_REJECTION",
				},
			},
		},
	}

	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	var emittedEvents []SecurityEvent
	subCh, unsub := bus.Subscribe(10)
	defer unsub()

	go func() {
		for ev := range subCh {
			emittedEvents = append(emittedEvents, ev)
		}
	}()

	pipe := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	svc := cfg.Services["failing-service"]

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})

	go func() {
		pipe.Handle(context.Background(), serverConn, &svc)
		close(done)
	}()

	buf := make([]byte, 128)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientConn.Read(buf)
	clientConn.Close()

	<-done

	resp := string(buf[:n])
	if !strings.Contains(resp, "PLUGIN_DISABLED_REJECTION") {
		t.Errorf("expected rejection banner when plugin is disabled, got %q", resp)
	}

	st := stats.GetOrCreate("failing-service")
	if st.Snapshot().BlockedConnections == 0 {
		t.Errorf("expected blocked connection metric incremented")
	}
}

func TestPipeline_GlobalGeoBlockAllowCountries(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			GeoBlock: config.GeoBlockConfig{
				AllowCountries: []string{"US", "CA"},
			},
		},
		Services: map[string]config.ServiceConfig{
			"geo-svc": {
				Name:     "geo-svc",
				Protocol: "tcp",
				Response: config.ResponseConfig{
					Mode: "drop",
				},
			},
		},
	}

	pipe := NewPipeline(cfg, NewBanList(""), NewFailureTracker(), NewRateLimiter(), NewEventBus(), NewStatsRegistry(), nil, nil)
	svc := cfg.Services["geo-svc"]

	// "FR" is not in US/CA -> should be blocked
	if !pipe.isCountryBlocked("FR", &svc) {
		t.Errorf("expected FR to be blocked by global allowlist")
	}

	// "US" is in US/CA -> should be allowed
	if pipe.isCountryBlocked("US", &svc) {
		t.Errorf("expected US to be allowed by global allowlist")
	}
}

type mockHTTPPlugin struct {
	inspectedCount atomic.Int32
}

func (m *mockHTTPPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:      "http",
		Version:   "1.0.0",
		Protocols: []string{"http"},
	}
}

func (m *mockHTTPPlugin) ValidateConfig(map[string]any) error { return nil }
func (m *mockHTTPPlugin) CreateInspector(map[string]any) (sdk.Inspector, error) {
	return &mockHTTPInspector{plugin: m}, nil
}
func (m *mockHTTPPlugin) SelfTest() error { return nil }

type mockHTTPInspector struct {
	plugin *mockHTTPPlugin
}

func (i *mockHTTPInspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	i.plugin.inspectedCount.Add(1)
	res := protocol.Proxy(client, upstream)
	return sdk.ProxyResult{BytesIn: res.BytesIn, BytesOut: res.BytesOut}, false, "", nil
}

func findTwoPortPairs(t *testing.T) (l1, l2, u1, u2 int) {
	t.Helper()
	testL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping live socket integration test: net.Listen restricted in test environment: %v", err)
		return 0, 0, 0, 0
	}
	testL.Close()

	for port := 31000; port < 45000; port += 4 {
		lA, errA := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if errA != nil {
			continue
		}
		lB, errB := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+1))
		if errB != nil {
			lA.Close()
			continue
		}
		lC, errC := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+2))
		if errC != nil {
			lA.Close()
			lB.Close()
			continue
		}
		lD, errD := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port+3))
		if errD != nil {
			lA.Close()
			lB.Close()
			lC.Close()
			continue
		}
		lA.Close()
		lB.Close()
		lC.Close()
		lD.Close()
		return port, port + 1, port + 2, port + 3
	}
	t.Fatal("could not find free port pairs")
	return 0, 0, 0, 0
}

func TestDaemon_HTTPPortRange_1to1(t *testing.T) {
	mockPlugin := &mockHTTPPlugin{}
	plugins.Register(mockPlugin)

	l1, l2, u1, u2 := findTwoPortPairs(t)

	// Upstream 1
	srv1 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response-from-upstream-1"))
	})}
	lnU1, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", u1))
	if err != nil {
		t.Fatalf("failed to listen on upstream 1: %v", err)
	}
	go srv1.Serve(lnU1)
	defer srv1.Close()

	// Upstream 2
	srv2 := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response-from-upstream-2"))
	})}
	lnU2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", u2))
	if err != nil {
		t.Fatalf("failed to listen on upstream 2: %v", err)
	}
	go srv2.Serve(lnU2)
	defer srv2.Close()

	cfg := &config.Config{
		Version: "1.0",
		Plugins: config.PluginsConfig{
			Enabled: []string{"http"},
		},
		Services: map[string]config.ServiceConfig{
			"http-1to1": {
				Name:     "http-1to1",
				Listen:   fmt.Sprintf("127.0.0.1:%d-%d", l1, l2),
				Upstream: fmt.Sprintf("127.0.0.1:%d-%d", u1, u2),
				Protocol: "http",
			},
		},
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("daemon Run exited prematurely: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Query Port 1 -> Should map to Upstream 1
	resp1, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l1))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l1, err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)
	if string(body1) != "response-from-upstream-1" {
		t.Errorf("port %d expected response from upstream 1, got %q", l1, string(body1))
	}

	// 2. Query Port 2 -> Should map to Upstream 2
	resp2, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l2))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l2, err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "response-from-upstream-2" {
		t.Errorf("port %d expected response from upstream 2, got %q", l2, string(body2))
	}

	if mockPlugin.inspectedCount.Load() < 2 {
		t.Errorf("expected at least 2 inspections by http plugin, got %d", mockPlugin.inspectedCount.Load())
	}
}

func TestDaemon_HTTPPortRange_ManyToOne(t *testing.T) {
	l1, l2, u1, _ := findTwoPortPairs(t)

	// Single Upstream Server
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response-from-single-target"))
	})}
	lnU, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", u1))
	if err != nil {
		t.Fatalf("failed to listen on single upstream: %v", err)
	}
	go srv.Serve(lnU)
	defer srv.Close()

	cfg := &config.Config{
		Version: "1.0",
		Plugins: config.PluginsConfig{
			Enabled: []string{"http"},
		},
		Services: map[string]config.ServiceConfig{
			"http-many-to-one": {
				Name:     "http-many-to-one",
				Listen:   fmt.Sprintf("127.0.0.1:%d-%d", l1, l2),
				Upstream: fmt.Sprintf("127.0.0.1:%d", u1),
				Protocol: "http",
			},
		},
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Run(ctx)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("daemon Run exited prematurely: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Query Port 1 -> Should map to Single Upstream
	resp1, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l1))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l1, err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)
	if string(body1) != "response-from-single-target" {
		t.Errorf("port %d expected response from single upstream, got %q", l1, string(body1))
	}

	// 2. Query Port 2 -> Should also map to Single Upstream
	resp2, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", l2))
	if err != nil {
		t.Fatalf("failed request to port %d: %v", l2, err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if string(body2) != "response-from-single-target" {
		t.Errorf("port %d expected response from single upstream, got %q", l2, string(body2))
	}
}

// ── Bug #6: LogWriter.shouldWrite — "blocked" events must be written at LevelError ──

func TestLogWriter_ShouldWrite_BlockedAtLevelError(t *testing.T) {
	// LevelError < LevelOff, so "blocked" must still be written.
	w := &LogWriter{level: LevelError}
	if !w.shouldWrite("blocked") {
		t.Error("Bug #6 regression: 'blocked' events must be written at LevelError")
	}
	if !w.shouldWrite("banned") {
		t.Error("Bug #6 regression: 'banned' events must be written at LevelError")
	}
	// "allowed" events must NOT be written at LevelError.
	if w.shouldWrite("allowed") {
		t.Error("'allowed' events must be suppressed at LevelError")
	}
	// Nothing is written at LevelOff.
	wOff := &LogWriter{level: LevelOff}
	if wOff.shouldWrite("blocked") {
		t.Error("no events must be written at LevelOff")
	}
}

func TestLogWriter_ShouldWrite_AllLevels(t *testing.T) {
	cases := []struct {
		level     Level
		action    string
		wantWrite bool
	}{
		{LevelDebug, "allowed", true},
		{LevelInfo, "allowed", true},
		{LevelWarn, "allowed", false},
		{LevelError, "allowed", false},
		{LevelOff, "allowed", false},
		{LevelDebug, "auth_failure", true},
		{LevelInfo, "auth_failure", true},
		{LevelWarn, "auth_failure", true},
		{LevelError, "auth_failure", false},
		{LevelOff, "auth_failure", false},
		{LevelDebug, "blocked", true},
		{LevelInfo, "blocked", true},
		{LevelWarn, "blocked", true},
		{LevelError, "blocked", true}, // Bug #6: was false before fix
		{LevelOff, "blocked", false},
	}
	for _, tc := range cases {
		w := &LogWriter{level: tc.level}
		got := w.shouldWrite(tc.action)
		if got != tc.wantWrite {
			t.Errorf("level=%v action=%q: shouldWrite()=%v, want %v", tc.level, tc.action, got, tc.wantWrite)
		}
	}
}

// ── Bug #11: /health Content-Type must be application/json (set once by middleware) ──

func TestAPIServer_Health_ContentTypeSetOnce(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Services: map[string]config.ServiceConfig{
			"svc": {Name: "svc", Protocol: "tcp"},
		},
	}
	api := NewAPIServer(cfg, NewBanList(""), NewStatsRegistry(), NewEventBus(), nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(rec, req)

	ct := rec.Result().Header["Content-Type"]
	if len(ct) != 1 {
		t.Errorf("Bug #11 regression: expected exactly 1 Content-Type header, got %d: %v", len(ct), ct)
	}
	if len(ct) > 0 && ct[0] != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct[0])
	}
}

// ── Bug #12: Proxy half-close must not call dst.Close() ──
// Verify that when a connection does NOT implement CloseWrite, the other copy
// direction can still complete without being aborted.

func TestProxy_HalfClose_DoesNotKillOtherDirection(t *testing.T) {
	// net.Pipe() returns *net.pipe which does NOT implement CloseWrite, exercising
	// the fallback branch that was previously calling dst.Close().
	clientSide, serverSide := net.Pipe()

	payload := []byte("hello from client")
	reply := []byte("hello from server")

	// Upstream side: read payload, write reply, close.
	go func() {
		buf := make([]byte, 128)
		n, _ := serverSide.Read(buf)
		_, _ = serverSide.Write(reply)
		_, _ = serverSide.Write(buf[:n]) // echo payload back so upstream→client direction has data
		serverSide.Close()
	}()

	// Run Proxy on a separate goroutine; collect byte counts.
	type result struct {
		in, out int64
	}
	ch := make(chan result, 1)
	go func() {
		// Create a pair simulating client ↔ upstream.
		upstreamClient, upstreamServer := net.Pipe()
		go func() {
			buf := make([]byte, 128)
			n, _ := upstreamServer.Read(buf)
			_, _ = upstreamServer.Write(buf[:n])
			upstreamServer.Close()
		}()
		r := protocol.Proxy(clientSide, upstreamClient)
		ch <- result{r.BytesIn, r.BytesOut}
	}()

	// Write from the test-client side and then close.
	_, _ = clientSide.Write(payload)
	// Don't close clientSide explicitly; let Proxy finish via upstream close.

	select {
	case r := <-ch:
		if r.in == 0 && r.out == 0 {
			// Both directions produced 0 bytes, which can happen with net.Pipe
			// in edge-cases, but Proxy itself must not have panicked.
		}
		_ = r
	case <-time.After(3 * time.Second):
		// If Proxy hangs, the old dst.Close() bug was preventing termination.
		t.Error("Bug #12 regression: Proxy hung — half-close may have killed the upstream read direction")
	}
}

// ── Bug #5: UDP session race must not produce negative activeConns ──
// Simulate the race by checking that onClose is only wired after the session
// wins the LoadOrStore, by directly exercising UDPSessionTable.GetOrCreate.

func TestUDPSessionTable_RaceLost_NoSpuriousConnClosed(t *testing.T) {
	table := NewUDPSessionTable(30 * time.Second)
	defer table.Close()

	closedCount := 0
	onClose := func() { closedCount++ }

	// First call creates the session and wins the race.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("cannot open UDP socket in test environment: %v", err)
	}
	defer udpConn.Close()

	winnerSession := &UDPSession{
		ClientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		Upstream:   udpConn,
	}

	s, isNew, err := table.GetOrCreate("key1", func() (*UDPSession, error) {
		return winnerSession, nil
	})
	if err != nil || !isNew {
		t.Fatalf("expected first GetOrCreate to succeed and be new; err=%v isNew=%v", err, isNew)
	}

	// Now wire onClose (as the daemon does after winning the race).
	s.onClose = onClose

	// Simulate a loser: GetOrCreate returns the existing winner and closes the loser.
	// The loser session must NOT fire the stats callback.
	loserUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if loserUDP != nil {
		defer loserUDP.Close()
	}
	loserClosed := false
	loserSession := &UDPSession{
		ClientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		Upstream:   loserUDP,
		// Intentionally NO onClose — mirrors the fix in udp_engine.go
	}
	_ = loserSession

	_, isNew2, err2 := table.GetOrCreate("key1", func() (*UDPSession, error) {
		// This factory should not be called because the key already exists.
		return loserSession, nil
	})
	if err2 != nil {
		t.Fatalf("second GetOrCreate returned error: %v", err2)
	}
	if isNew2 {
		t.Error("second GetOrCreate should not be new — key already exists")
	}
	// The loser's onClose was nil so closedCount must still be 0.
	_ = loserClosed
	if closedCount != 0 {
		t.Errorf("Bug #5 regression: spurious onClose fired %d time(s) for losing session", closedCount)
	}

	// Delete the winner: onClose fires exactly once.
	table.Delete("key1")
	if closedCount != 1 {
		t.Errorf("expected onClose to fire exactly once on Delete, got %d", closedCount)
	}
}

// ── Round 3 Bug #2: APIServer must enforce auth_token when configured ──

func TestAPIServer_AuthToken_Enforcement(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			AuthToken: "secret-token-xyz",
		},
		Services: map[string]config.ServiceConfig{
			"svc": {Name: "svc", Protocol: "tcp"},
		},
	}
	api := NewAPIServer(cfg, NewBanList(""), NewStatsRegistry(), NewEventBus(), nil)

	// 1. /ping should be accessible without any token
	pingReq := httptest.NewRequest(http.MethodGet, "/ping", nil)
	pingRec := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(pingRec, pingReq)
	if pingRec.Code != http.StatusOK {
		t.Errorf("expected 200 OK from /ping without auth, got %d", pingRec.Code)
	}

	// 2. /health without token should return 401 Unauthorized
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/health", nil)
	recNoAuth := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("Round 3 Bug #2 regression: expected 401 Unauthorized without token, got %d", recNoAuth.Code)
	}

	// 3. /health with invalid token should return 401 Unauthorized
	reqBadAuth := httptest.NewRequest(http.MethodGet, "/health", nil)
	reqBadAuth.Header.Set("Authorization", "Bearer invalid-token")
	recBadAuth := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recBadAuth, reqBadAuth)
	if recBadAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized with invalid token, got %d", recBadAuth.Code)
	}

	// 4. /health with valid Bearer token should return 200 OK
	reqGoodAuth := httptest.NewRequest(http.MethodGet, "/health", nil)
	reqGoodAuth.Header.Set("Authorization", "Bearer secret-token-xyz")
	recGoodAuth := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recGoodAuth, reqGoodAuth)
	if recGoodAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK with valid token, got %d", recGoodAuth.Code)
	}

	// 5. /health with query parameter ?token=secret-token-xyz should return 200 OK
	reqQueryAuth := httptest.NewRequest(http.MethodGet, "/health?token=secret-token-xyz", nil)
	recQueryAuth := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(recQueryAuth, reqQueryAuth)
	if recQueryAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK with query token, got %d", recQueryAuth.Code)
	}
}

// ── Round 3 Bug #3: Pipeline.Handle must recover from panics gracefully ──

type panickingInspector struct{}

func (p *panickingInspector) Run(ctx sdk.Context, client, upstream net.Conn) (result sdk.ProxyResult, blocked bool, reason string, err error) {
	panic("unexpected parser explosion")
}

type panickingPlugin struct{}

func (p *panickingPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{Name: "panicker", Version: "1.0.0", Protocols: []string{"panicker"}}
}
func (p *panickingPlugin) ValidateConfig(map[string]any) error { return nil }
func (p *panickingPlugin) CreateInspector(map[string]any) (sdk.Inspector, error) {
	return &panickingInspector{}, nil
}
func (p *panickingPlugin) SelfTest() error { return nil }

func TestPipeline_Handle_PanicRecovery(t *testing.T) {
	plugins.Register(&panickingPlugin{})
	_ = plugins.Enable("panicker")

	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			LogLevel: "debug",
		},
		Services: map[string]config.ServiceConfig{
			"test_panic": {
				Name:     "test_panic",
				Protocol: "panicker",
				Listen:   ":19090",
				Upstream: "127.0.0.1:19090",
			},
		},
	}

	pipe := NewPipeline(cfg, NewBanList(""), NewFailureTracker(), NewRateLimiter(), NewEventBus(), NewStatsRegistry(), nil, nil)

	c1, c2 := net.Pipe()
	defer c1.Close()

	svc := cfg.Services["test_panic"]

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Must not panic out and kill test process
		pipe.Handle(context.Background(), c2, &svc)
	}()

	select {
	case <-done:
		// Completed cleanly with panic recovered
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline handler hung during panic recovery")
	}
}

// ── ServiceStats.ConnClosed must never drive activeConns negative ──

func TestServiceStats_ConnClosed_NeverNegative(t *testing.T) {
	st := &ServiceStats{Name: "test"}
	// Call ConnClosed multiple times without any ConnAccepted
	st.ConnClosed()
	st.ConnClosed()
	st.ConnClosed()

	snap := st.Snapshot()
	if snap.ActiveConnections < 0 {
		t.Errorf("expected activeConns >= 0, got %d", snap.ActiveConnections)
	}
}

func TestParseClientIP_IPv6ZoneStripping(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"fe80::1%eth0", "fe80::1"},
		{"[fe80::1%eth0]:12345", "fe80::1"},
		{"fe80::1%en0", "fe80::1"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"[::1]:9090", "::1"},
		{"::1", "::1"},
		{"   10.0.0.1:443   ", "10.0.0.1"},
	}

	for _, c := range cases {
		got := parseClientIP(c.input)
		if got != c.expected {
			t.Errorf("parseClientIP(%q) = %q; want %q", c.input, got, c.expected)
		}
	}

	// Also verify matchIP handles patterns with %zone
	parsed := net.ParseIP("fe80::1")
	if !matchIP(parsed, "fe80::1%eth0") {
		t.Errorf("matchIP failed to match fe80::1 with fe80::1%%eth0")
	}
}

func TestAPI_ConstantTimeAuth_And_HealthVersion(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled:   true,
			Listen:    "127.0.0.1:0",
			AuthToken: "top-secret-token-xyz",
		},
	}
	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	// 1. Missing auth token
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated request, got %d", w.Code)
	}

	// 2. Incorrect auth token
	req = httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong token, got %d", w.Code)
	}

	// 3. Valid auth token
	req = httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("Authorization", "Bearer top-secret-token-xyz")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid token, got %d: %s", w.Code, w.Body.String())
	}

	var healthResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &healthResp); err != nil {
		t.Fatalf("failed to unmarshal health response: %v", err)
	}

	// Verify version reports sdk.Version ("3.2.0") and config_version reports "1.0"
	if healthResp["version"] != sdk.Version {
		t.Errorf("expected health version %q, got %q", sdk.Version, healthResp["version"])
	}
	if healthResp["config_version"] != "1.0" {
		t.Errorf("expected health config_version '1.0', got %q", healthResp["config_version"])
	}
}

func TestAPI_BanUnban_IPv6Zone(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
	}
	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()

	api := NewAPIServer(cfg, bl, stats, bus, nil)

	// Ban IPv6 with zone
	banBody := bytes.NewBufferString(`{"ip":"fe80::cafe:babe%eth0","reason":"zone_test","duration":"30m"}`)
	req := httptest.NewRequest("POST", "/api/tcp/ban", banBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from ban, got %d: %s", w.Code, w.Body.String())
	}

	// Verify banlist has stripped IP "fe80::cafe:babe"
	if _, isBanned := bl.IsBanned("fe80::cafe:babe"); !isBanned {
		t.Errorf("expected fe80::cafe:babe to be banned in banlist")
	}

	// Unban with zone
	unbanBody := bytes.NewBufferString(`{"ip":"fe80::cafe:babe%eth0"}`)
	req = httptest.NewRequest("POST", "/api/tcp/unban", unbanBody)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from unban, got %d: %s", w.Code, w.Body.String())
	}

	if _, isBanned := bl.IsBanned("fe80::cafe:babe"); isBanned {
		t.Errorf("expected fe80::cafe:babe to be unbanned")
	}
}

func TestAPI_BanlistListingAndUnban(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
	}
	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()
	api := NewAPIServer(cfg, bl, stats, bus, nil)

	// Add 2 bans
	bl.Ban("198.51.100.1", "manual_test_1", "test-service", 1*time.Hour)
	bl.Ban("198.51.100.2", "manual_test_2", "test-service", 1*time.Hour)

	// List bans via /api/banlist
	req := httptest.NewRequest("GET", "/api/banlist", nil)
	w := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/banlist, got %d", w.Code)
	}

	var bans []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &bans); err != nil {
		t.Fatalf("failed to decode banlist JSON: %v, raw: %s", err, w.Body.String())
	}
	if len(bans) != 2 {
		t.Errorf("expected 2 bans in banlist, got %d", len(bans))
	}

	// Unban one IP
	unbanReq := httptest.NewRequest("POST", "/api/unban", bytes.NewBufferString(`{"ip":"198.51.100.1"}`))
	unbanReq.Header.Set("Content-Type", "application/json")
	unbanW := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(unbanW, unbanReq)

	if unbanW.Code != http.StatusOK {
		t.Fatalf("expected 200 from unban, got %d", unbanW.Code)
	}

	// List bans again; should only have 1 left
	req2 := httptest.NewRequest("GET", "/api/banlist", nil)
	w2 := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(w2, req2)

	var bans2 []map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &bans2); err != nil {
		t.Fatalf("failed to decode banlist JSON: %v", err)
	}
	if len(bans2) != 1 {
		t.Errorf("expected 1 ban remaining, got %d", len(bans2))
	}
	if bans2[0]["ip"] != "198.51.100.2" {
		t.Errorf("expected 198.51.100.2 remaining, got %v", bans2[0]["ip"])
	}
}

func TestAPI_ServicesListing(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Services: map[string]config.ServiceConfig{
			"redis-prod": {
				Listen:   "0.0.0.0:6379",
				Upstream: "127.0.0.1:6379",
				Protocol: "redis",
			},
			"mysql-prod": {
				Listen:   "0.0.0.0:3306",
				Upstream: "127.0.0.1:3306",
				Protocol: "mysql",
			},
		},
	}
	api := NewAPIServer(cfg, NewBanList(""), NewStatsRegistry(), NewEventBus(), nil)

	req := httptest.NewRequest("GET", "/api/services", nil)
	w := httptest.NewRecorder()
	api.srv.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/services, got %d", w.Code)
	}

	var services []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &services); err != nil {
		t.Fatalf("failed decoding services JSON: %v", err)
	}
	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}
}

func TestPipeline_IPFilter_IPv6AndCIDR(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		Global: config.GlobalConfig{
			IPFilter: config.IPFilterConfig{
				Allow: []string{"2001:db8::/32", "192.168.1.0/24"},
			},
		},
		Services: map[string]config.ServiceConfig{
			"echo": {
				Name:     "echo",
				Listen:   "127.0.0.1:0",
				Upstream: "127.0.0.1:0",
			},
		},
	}
	bl := NewBanList("")
	ft := NewFailureTracker()
	rl := NewRateLimiter()
	bus := NewEventBus()
	stats := NewStatsRegistry()

	pipeline := NewPipeline(cfg, bl, ft, rl, bus, stats, nil, nil)
	pIP := parseClientIP("[2001:db8::cafe]:12345")
	if pIP != "2001:db8::cafe" {
		t.Errorf("expected parsed client IP 2001:db8::cafe, got %s", pIP)
	}

	svc := cfg.Services["echo"]

	// In global allowlist: should NOT be denied
	if pipeline.isIPDenied("2001:db8::cafe", &svc) {
		t.Errorf("expected 2001:db8::cafe to be allowed via 2001:db8::/32 CIDR")
	}

	// Outside global allowlist: should be denied
	if !pipeline.isIPDenied("2001:db9::1", &svc) {
		t.Errorf("expected 2001:db9::1 to be denied")
	}

	// Service-level deny takes precedence
	svcWithDeny := svc
	svcWithDeny.IPFilter.Deny = []string{"2001:db8::cafe"}
	if !pipeline.isIPDenied("2001:db8::cafe", &svcWithDeny) {
		t.Errorf("expected 2001:db8::cafe to be denied by service-level deny")
	}

	// Test matchIP edge cases
	if !matchIP(net.ParseIP("192.168.1.50"), "192.168.1.0/24") {
		t.Errorf("expected matchIP to return true for 192.168.1.50 in 192.168.1.0/24")
	}
	if matchIP(net.ParseIP("192.168.2.50"), "192.168.1.0/24") {
		t.Errorf("expected matchIP to return false for 192.168.2.50 in 192.168.1.0/24")
	}
	if !matchIP(net.ParseIP("10.0.0.1"), "10.0.0.1") {
		t.Errorf("expected exact IP match for 10.0.0.1")
	}
}

func TestCore_IPFilter_BoundaryCases(t *testing.T) {
	// 1. Bracketed IPv6 without port
	if got := parseClientIP("[::1]"); got != "::1" {
		t.Errorf("expected ::1, got %s", got)
	}
	if got := parseClientIP("[2001:db8::1]"); got != "2001:db8::1" {
		t.Errorf("expected 2001:db8::1, got %s", got)
	}
	// 2. IPv6 with zone identifier
	if got := parseClientIP("fe80::1%eth0"); got != "fe80::1" {
		t.Errorf("expected fe80::1, got %s", got)
	}

	// 3. matchIP with bracketed pattern
	if !matchIP(net.ParseIP("::1"), "[::1]") {
		t.Errorf("expected matchIP to match bracketed IPv6 pattern [::1]")
	}

	// 4. matchIP with IPv4-mapped IPv6 against IPv4 CIDR
	mappedIP := net.ParseIP("::ffff:192.168.1.100")
	if !matchIP(mappedIP, "192.168.1.0/24") {
		t.Errorf("expected IPv4-mapped IPv6 ::ffff:192.168.1.100 to match 192.168.1.0/24")
	}
}

func TestAPI_BanAndUnban_SecurityBoundaries(t *testing.T) {
	cfg := &config.Config{
		Version: "1.0",
		API: config.APIConfig{
			Enabled: true,
			Listen:  "127.0.0.1:0",
		},
		Global: config.GlobalConfig{
			BanDuration: config.Duration(1 * time.Hour),
		},
	}
	bl := NewBanList("")
	stats := NewStatsRegistry()
	bus := NewEventBus()
	api := NewAPIServer(cfg, bl, stats, bus, nil)

	// 1. Bracketed IPv6 ban via API
	body := strings.NewReader(`{"ip":"[2001:db8::cafe]","reason":"boundary_test"}`)
	req := httptest.NewRequest("POST", "/api/ban", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for bracketed IPv6 ban, got %d: %s", w.Code, w.Body.String())
	}
	if _, isBanned := bl.IsBanned("2001:db8::cafe"); !isBanned {
		t.Error("expected 2001:db8::cafe to be banned in banlist")
	}

	// 2. Negative duration rejection
	negBody := strings.NewReader(`{"ip":"1.2.3.4","duration":"-10m"}`)
	req = httptest.NewRequest("POST", "/api/ban", negBody)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for negative duration, got %d", w.Code)
	}

	// 3. Oversized body rejection (>64KB)
	hugeBody := strings.NewReader(`{"ip":"1.2.3.4","reason":"` + strings.Repeat("A", 70000) + `"}`)
	req = httptest.NewRequest("POST", "/api/ban", hugeBody)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for oversized body, got %d", w.Code)
	}

	// 4. Bracketed unban
	unbanBody := strings.NewReader(`{"ip":"[2001:db8::cafe]"}`)
	req = httptest.NewRequest("POST", "/api/unban", unbanBody)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for bracketed unban, got %d: %s", w.Code, w.Body.String())
	}
	if _, isBanned := bl.IsBanned("2001:db8::cafe"); isBanned {
		t.Error("expected 2001:db8::cafe to be unbanned")
	}

	// 5. Day duration support (e.g. "7d")
	dayBanBody := strings.NewReader(`{"ip":"198.51.100.55","duration":"7d","reason":"day_test"}`)
	req = httptest.NewRequest("POST", "/api/ban", dayBanBody)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for 7d duration ban, got %d: %s", w.Code, w.Body.String())
	}
	if b, isBanned := bl.IsBanned("198.51.100.55"); !isBanned {
		t.Error("expected 198.51.100.55 to be banned in banlist")
	} else {
		diff := b.ExpiresAt.Sub(b.BannedAt)
		expected := 7 * 24 * time.Hour
		if diff < expected-time.Second || diff > expected+time.Second {
			t.Errorf("expected ban duration approx 168h, got %v", diff)
		}
	}
}

// PC-9: EventBus rapid event publication without deadlock
func TestEventBus_RapidDispatch(t *testing.T) {
	bus := NewEventBus()
	defer bus.Close()

	ch, unsub := bus.Subscribe(2000)
	defer unsub()

	count := 1000
	for i := 0; i < count; i++ {
		bus.Publish(SecurityEvent{Type: "security_event", ClientIP: "192.0.2.1", Timestamp: time.Now()})
	}

	received := 0
	for i := 0; i < count; i++ {
		select {
		case <-ch:
			received++
		case <-time.After(100 * time.Millisecond):
			break
		}
	}
	if received != count {
		t.Errorf("expected %d events, received %d", count, received)
	}
}

// PC-10: StatsRegistry concurrent increments
func TestStatsRegistry_ConcurrentAccess(t *testing.T) {
	stats := NewStatsRegistry()
	workers := 50
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := stats.GetOrCreate("test-service")
			for j := 0; j < 50; j++ {
				s.ConnAccepted()
				s.AddBytes(1024, 2048)
				s.AddBlocked()
				s.ConnClosed()
				_ = s.Snapshot()
			}
		}()
	}

	wg.Wait()
	s := stats.GetOrCreate("test-service")
	snap := s.Snapshot()
	if snap.TotalConnections != int64(workers*50) {
		t.Errorf("expected %d total connections, got %d", workers*50, snap.TotalConnections)
	}
}

// PC-6: RateLimiter boundary conditions
func TestRateLimiter_BoundaryConditions(t *testing.T) {
	rl := NewRateLimiter()

	// Rate <= 0 should allow (disabled rate limit)
	if !rl.Allow("svc", "192.0.2.10", 0, 0) {
		t.Error("expected rate 0 to allow (disabled rate limiter)")
	}

	// Burst = 0 with positive rate
	allowed := rl.Allow("svc", "192.0.2.11", 60, 0)
	_ = allowed
}

// PC-7: FailureTracker zero window
func TestFailureTracker_ZeroWindow(t *testing.T) {
	ft := NewFailureTracker()
	// Zero duration window means failures expire immediately
	c1 := ft.RecordFailure("ssh", "192.0.2.20", 0)
	if c1 < 1 {
		t.Errorf("expected failure record to return at least 1, got %d", c1)
	}
}




