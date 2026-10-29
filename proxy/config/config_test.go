package config

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/routewarden/cli/proxy/plugins"
	"github.com/routewarden/cli/proxy/plugins/sdk"
	"gopkg.in/yaml.v3"
)

type mockValidationPlugin struct{}

func (m *mockValidationPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:      "postgres",
		Version:   "1.0.0",
		Protocols: []string{"postgres"},
	}
}

func (m *mockValidationPlugin) ValidateConfig(map[string]any) error { return nil }
func (m *mockValidationPlugin) CreateInspector(map[string]any) (sdk.Inspector, error) {
	return nil, nil
}
func (m *mockValidationPlugin) SelfTest() error { return nil }

type mockTestPlugin struct {
	name      string
	protocols []string
}

func (m *mockTestPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{Name: m.name, Version: "1.0.0", Protocols: m.protocols}
}
func (m *mockTestPlugin) ValidateConfig(map[string]any) error { return nil }
func (m *mockTestPlugin) CreateInspector(map[string]any) (sdk.Inspector, error) { return nil, nil }
func (m *mockTestPlugin) SelfTest() error { return nil }

func init() {
	plugins.Register(&mockValidationPlugin{})
	plugins.Register(&mockTestPlugin{name: "ftp", protocols: []string{"ftp"}})
	plugins.Register(&mockTestPlugin{name: "redis", protocols: []string{"redis"}})
}

func TestParseYAML(t *testing.T) {
	os.Setenv("TEST_LAPI_KEY", "secret-key-123")
	defer os.Unsetenv("TEST_LAPI_KEY")

	yamlData := `
version: "1.0"

global:
  max_connections: 5000
  ban_duration: "2h"
  ban_after_failures: 5
  log_file: "/tmp/tcp-warden.jsonl"
  ip_filter:
    allow:
      - "127.0.0.1"
      - "10.0.0.0/8"

api:
  enabled: true
  listen: ":9091"

crowdsec:
  enabled: true
  lapi_url: "http://127.0.0.1:8080"
  api_key: "${TEST_LAPI_KEY}"
  update_frequency: "15s"

services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
    rate_limit:
      connections_per_minute: 20
      burst: 5
    ip_filter:
      deny:
        - "198.51.100.0/24"
    geo_block:
      deny_countries:
        - "CN"
        - "RU"
    ssh:
      banner: "RouteWarden SSH"
      max_auth_tries: 3

  smtp:
    listen: ":2525"
    upstream: "127.0.0.1:25"
    protocol: "smtp"
    response:
      mode: "reject"
      reject_message: "554 Rejected"
`

	cfg, err := Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("Failed to parse valid YAML: %v", err)
	}

	if cfg.Global.MaxConnections != 5000 {
		t.Errorf("Expected MaxConnections 5000, got %d", cfg.Global.MaxConnections)
	}
	if cfg.Global.BanDuration.Duration() != 2*time.Hour {
		t.Errorf("Expected BanDuration 2h, got %v", cfg.Global.BanDuration.Duration())
	}
	if cfg.CrowdSec.APIKey != "secret-key-123" {
		t.Errorf("Expected CrowdSec APIKey 'secret-key-123', got %q", cfg.CrowdSec.APIKey)
	}
	if cfg.CrowdSec.UpdateFrequency.Duration() != 15*time.Second {
		t.Errorf("Expected UpdateFrequency 15s, got %v", cfg.CrowdSec.UpdateFrequency.Duration())
	}

	sshSvc, ok := cfg.Services["ssh"]
	if !ok {
		t.Fatalf("Expected 'ssh' service in map")
	}
	if sshSvc.Protocol != "ssh" {
		t.Errorf("Expected protocol 'ssh', got %q", sshSvc.Protocol)
	}
	if sshSvc.RateLimit.ConnectionsPerMinute != 20 {
		t.Errorf("Expected 20 conns/min, got %d", sshSvc.RateLimit.ConnectionsPerMinute)
	}
	if len(sshSvc.GeoBlock.DenyCountries) != 2 {
		t.Errorf("Expected 2 denied countries, got %d", len(sshSvc.GeoBlock.DenyCountries))
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty services",
			yaml:    `version: "1.0"`,
			wantErr: "no services defined",
		},
		{
			name: "duplicate listen address",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
  svc2:
    listen: ":2222"
    upstream: "127.0.0.1:23"
`,
			wantErr: "duplicate listen address",
		},
		{
			name: "invalid CIDR",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    ip_filter:
      allow: ["not-an-ip"]
`,
			wantErr: "invalid allowed IP/CIDR",
		},
		{
			name: "invalid service deny CIDR",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    ip_filter:
      deny: ["999.999.999.999/24"]
`,
			wantErr: "invalid denied IP/CIDR",
		},
		{
			name: "invalid global allow CIDR",
			yaml: `
global:
  ip_filter:
    allow: ["192.168.1.1/33"]
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
`,
			wantErr: "global: invalid allowed IP/CIDR",
		},
		{
			name: "invalid global deny CIDR",
			yaml: `
global:
  ip_filter:
    deny: ["bad-cidr"]
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
`,
			wantErr: "global: invalid denied IP/CIDR",
		},
		{
			name: "unsupported response mode",
			yaml: `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    response:
      mode: "destroy"
`,
			wantErr: "unsupported response mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !testingContains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestPluginWarnings(t *testing.T) {
	t.Run("uninstalled plugin produces warning instead of failing validation", func(t *testing.T) {
		yamlData := `
services:
  svc1:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "unknown_proto"
`
		cfg, err := Parse([]byte(yamlData))
		if err != nil {
			t.Fatalf("expected Parse to succeed without crashing/error, got: %v", err)
		}
		if len(cfg.Warnings) == 0 {
			t.Fatalf("expected warnings for uninstalled plugin, got none")
		}
		if !strings.Contains(cfg.Warnings[0], "requires plugin") {
			t.Errorf("expected warning containing 'requires plugin', got: %s", cfg.Warnings[0])
		}
	})

	t.Run("disabled plugin produces warning instead of failing validation", func(t *testing.T) {
		yamlData := `
services:
  svc1:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
`
		cfg, err := Parse([]byte(yamlData))
		if err != nil {
			t.Fatalf("expected Parse to succeed without crashing/error, got: %v", err)
		}
		if len(cfg.Warnings) == 0 {
			t.Fatalf("expected warnings for disabled plugin, got none")
		}
		if !strings.Contains(cfg.Warnings[0], "which is DISABLED by default") {
			t.Errorf("expected warning containing 'which is DISABLED by default', got: %s", cfg.Warnings[0])
		}
	})
}

func TestPluginEnablementValidation(t *testing.T) {
	yamlData := `
version: "1.0"
plugins:
  postgres:
    enabled: true
  mongodb:
    enabled: true
    source: "https://github.com/routewarden/plugin-mongodb"
services:
  db:
    listen: ":5433"
    upstream: "127.0.0.1:5432"
    protocol: "postgres"
`
	cfg, err := Parse([]byte(yamlData))
	if err != nil {
		t.Fatalf("expected enabled plugin configuration to pass validation, got: %v", err)
	}
	if !cfg.IsPluginEnabled("postgres") {
		t.Errorf("expected postgres to be enabled")
	}
	if cfg.Plugins.Entries["mongodb"].Source != "https://github.com/routewarden/plugin-mongodb" {
		t.Errorf("expected mongodb source to be parsed, got %s", cfg.Plugins.Entries["mongodb"].Source)
	}
}

func TestUpdatePluginEnablement(t *testing.T) {
	initialYAML := `# Header comment
version: "1.0"

# Plugin section comment
plugins:
  postgres:
    enabled: false # inline comment
  mysql:
    enabled: false

services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
`
	tmpFile, err := os.CreateTemp("", "tcp-warden-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(initialYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// 1. Enable postgres
	if err := UpdatePluginEnablement(tmpFile.Name(), "postgres", true); err != nil {
		t.Fatalf("failed to update postgres to true: %v", err)
	}

	cfg1, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	if !cfg1.IsPluginEnabled("postgres") {
		t.Errorf("expected postgres to be enabled after UpdatePluginEnablement")
	}

	// 2. Add a new plugin: redis -> true
	if err := UpdatePluginEnablement(tmpFile.Name(), "redis", true); err != nil {
		t.Fatalf("failed to update redis to true: %v", err)
	}

	cfg2, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	if !cfg2.IsPluginEnabled("redis") {
		t.Errorf("expected redis to be enabled after UpdatePluginEnablement")
	}

	// 3. Disable postgres again
	if err := UpdatePluginEnablement(tmpFile.Name(), "postgres", false); err != nil {
		t.Fatalf("failed to disable postgres: %v", err)
	}

	cfg3, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	if cfg3.IsPluginEnabled("postgres") {
		t.Errorf("expected postgres to be disabled after UpdatePluginEnablement(false)")
	}

	// 4. Verify comments were preserved
	content, _ := os.ReadFile(tmpFile.Name())
	if !strings.Contains(string(content), "# Header comment") {
		t.Errorf("expected comments to be preserved in YAML")
	}
}

func TestUpdatePluginEnablement_Variants(t *testing.T) {
	t.Run("plugins empty mapping format", func(t *testing.T) {
		initialYAML := `version: "1.0"
plugins: {}
services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
`
		tmp, err := os.CreateTemp("", "test-empty-map-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmp.Name())
		_ = os.WriteFile(tmp.Name(), []byte(initialYAML), 0644)

		if err := UpdatePluginEnablement(tmp.Name(), "postgres", true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err := Load(tmp.Name())
		if err != nil {
			t.Fatalf("failed loading updated config: %v", err)
		}
		if !cfg.IsPluginEnabled("postgres") {
			t.Errorf("expected postgres to be enabled")
		}

		// Disable it
		if err := UpdatePluginEnablement(tmp.Name(), "postgres", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err = Load(tmp.Name())
		if err != nil {
			t.Fatalf("failed loading updated config: %v", err)
		}
		if cfg.IsPluginEnabled("postgres") {
			t.Errorf("expected postgres to be disabled")
		}
	})

	t.Run("missing plugins section", func(t *testing.T) {
		initialYAML := `version: "1.0"
services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
`
		tmp, err := os.CreateTemp("", "test-missing-sec-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmp.Name())
		_ = os.WriteFile(tmp.Name(), []byte(initialYAML), 0644)

		if err := UpdatePluginEnablement(tmp.Name(), "redis", true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err := Load(tmp.Name())
		if err != nil {
			t.Fatalf("failed loading updated config: %v", err)
		}
		if !cfg.IsPluginEnabled("redis") {
			t.Errorf("expected redis to be enabled")
		}
	})

	t.Run("sequence format", func(t *testing.T) {
		initialYAML := `version: "1.0"
plugins:
  - postgres
services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
`
		tmp, err := os.CreateTemp("", "test-seq-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmp.Name())
		_ = os.WriteFile(tmp.Name(), []byte(initialYAML), 0644)

		// Add redis
		if err := UpdatePluginEnablement(tmp.Name(), "redis", true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err := Load(tmp.Name())
		if err != nil {
			t.Fatalf("failed loading updated config: %v", err)
		}
		if !cfg.IsPluginEnabled("redis") || !cfg.IsPluginEnabled("postgres") {
			t.Errorf("expected redis and postgres to be enabled")
		}

		// Disable postgres
		if err := UpdatePluginEnablement(tmp.Name(), "postgres", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err = Load(tmp.Name())
		if err != nil {
			t.Fatalf("failed loading updated config: %v", err)
		}
		if cfg.IsPluginEnabled("postgres") {
			t.Errorf("expected postgres to be disabled")
		}
	})

	t.Run("disabled list synchronization", func(t *testing.T) {
		initialYAML := `version: "1.0"
plugins:
  disabled:
    - postgres
    - redis
services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
`
		tmp, err := os.CreateTemp("", "test-disabled-sync-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmp.Name())
		_ = os.WriteFile(tmp.Name(), []byte(initialYAML), 0644)

		// Enable postgres
		if err := UpdatePluginEnablement(tmp.Name(), "postgres", true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err := Load(tmp.Name())
		if err != nil {
			t.Fatalf("failed loading updated config: %v", err)
		}
		if !cfg.IsPluginEnabled("postgres") {
			t.Errorf("expected postgres to be enabled after removing from disabled list")
		}
		if cfg.IsPluginEnabled("redis") {
			t.Errorf("expected redis to remain disabled")
		}
	})
}

func TestAddDefaultPluginService(t *testing.T) {
	initialYAML := `version: "1.0"
services:
  ssh:
    listen: ":2222"
    upstream: "127.0.0.1:22"
    protocol: "ssh"
`
	tmp, err := os.CreateTemp("", "test-add-default-svc-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	_ = os.WriteFile(tmp.Name(), []byte(initialYAML), 0644)

	// 1. Enable FTP and add FTP default service
	_ = UpdatePluginEnablement(tmp.Name(), "ftp", true)
	added, name, err := AddDefaultPluginService(tmp.Name(), "ftp", nil)
	if err != nil {
		t.Fatalf("AddDefaultPluginService failed: %v", err)
	}
	if !added || name != "ftp" {
		t.Fatalf("expected ftp service to be added, got added=%v name=%s", added, name)
	}

	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("failed loading config after adding service: %v", err)
	}
	svc, ok := cfg.Services["ftp"]
	if !ok {
		t.Fatalf("expected ftp service in loaded config")
	}
	if svc.Listen != ":2121" || svc.Upstream != "127.0.0.1:21" || svc.Protocol != "ftp" {
		t.Errorf("unexpected ftp service config: %+v", svc)
	}

	// 2. Calling again should be idempotent and not duplicate
	addedAgain, _, err := AddDefaultPluginService(tmp.Name(), "ftp", nil)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if addedAgain {
		t.Errorf("expected second call to not add duplicate service")
	}

	// 3. Enable Redis and add Redis with plugin_config
	_ = UpdatePluginEnablement(tmp.Name(), "redis", true)
	addedRedis, redisName, err := AddDefaultPluginService(tmp.Name(), "redis", nil)
	if err != nil {
		t.Fatalf("AddDefaultPluginService for redis failed: %v", err)
	}
	if !addedRedis || redisName != "redis" {
		t.Fatalf("expected redis service to be added, got added=%v name=%s", addedRedis, redisName)
	}

	cfg2, err := Load(tmp.Name())
	if err != nil {
		t.Fatalf("failed loading config after adding redis: %v", err)
	}
	rSvc, ok := cfg2.Services["redis"]
	if !ok {
		t.Fatalf("expected redis service in loaded config")
	}
	if rSvc.Listen != ":6380" || rSvc.Protocol != "redis" {
		t.Errorf("unexpected redis service config: %+v", rSvc)
	}
	if len(rSvc.PluginConfig) == 0 {
		t.Errorf("expected redis plugin_config to be preserved")
	}
}

func testingContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && (s[:len(substr)] == substr || testingContains(s[1:], substr))))
}

func TestPortRangeParsing(t *testing.T) {
	tests := []struct {
		addr      string
		wantHost  string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{addr: ":8080", wantHost: "", wantStart: 8080, wantEnd: 8080},
		{addr: "8080", wantHost: "", wantStart: 8080, wantEnd: 8080},
		{addr: ":8000-8005", wantHost: "", wantStart: 8000, wantEnd: 8005},
		{addr: "127.0.0.1:8080", wantHost: "127.0.0.1", wantStart: 8080, wantEnd: 8080},
		{addr: "127.0.0.1:8000-8005", wantHost: "127.0.0.1", wantStart: 8000, wantEnd: 8005},
		{addr: "[::1]:8000-8005", wantHost: "::1", wantStart: 8000, wantEnd: 8005},
		{addr: "", wantErr: true},
		{addr: ":abc", wantErr: true},
		{addr: ":8005-8000", wantErr: true},
		{addr: ":0", wantErr: true},
		{addr: ":70000", wantErr: true},
		{addr: ":1-2000", wantErr: true}, // exceeds 1000 max span
	}

	for _, tt := range tests {
		h, start, end, err := ParsePortRange(tt.addr)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePortRange(%q) expected error, got nil", tt.addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q) unexpected error: %v", tt.addr, err)
			continue
		}
		if h != tt.wantHost || start != tt.wantStart || end != tt.wantEnd {
			t.Errorf("ParsePortRange(%q) = (%q, %d, %d), want (%q, %d, %d)", tt.addr, h, start, end, tt.wantHost, tt.wantStart, tt.wantEnd)
		}
	}
}

func TestResolveUpstream(t *testing.T) {
	// 1:1 range
	svc1 := ServiceConfig{
		Listen:   ":8000-8003",
		Upstream: "10.0.0.1:9000-9003",
	}

	target, err := svc1.ResolveUpstream(&net.TCPAddr{Port: 8002})
	if err != nil || target != "10.0.0.1:9002" {
		t.Errorf("ResolveUpstream 1:1 port 8002 = %q, err=%v, want 10.0.0.1:9002", target, err)
	}

	// Many-to-one
	svc2 := ServiceConfig{
		Listen:   ":8000-8005",
		Upstream: "10.0.0.1:8080",
	}
	target2, err := svc2.ResolveUpstream(&net.TCPAddr{Port: 8004})
	if err != nil || target2 != "10.0.0.1:8080" {
		t.Errorf("ResolveUpstream many-to-one port 8004 = %q, err=%v, want 10.0.0.1:8080", target2, err)
	}
}

func TestPortRangeValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "valid 1:1 port range",
			yaml: `
services:
  http_range:
    listen: ":8000-8002"
    upstream: "127.0.0.1:9000-9002"
    protocol: "tcp"
`,
		},
		{
			name: "valid many-to-one port range",
			yaml: `
services:
  http_many:
    listen: ":8000-8005"
    upstream: "127.0.0.1:8080"
    protocol: "tcp"
`,
		},
		{
			name: "single listen to range upstream error",
			yaml: `
services:
  invalid:
    listen: ":8080"
    upstream: "127.0.0.1:9000-9005"
    protocol: "tcp"
`,
			wantErr: "single listen port cannot map to an upstream port range",
		},
		{
			name: "mismatched range sizes error",
			yaml: `
services:
  mismatch:
    listen: ":8000-8005"
    upstream: "127.0.0.1:9000-9002"
    protocol: "tcp"
`,
			wantErr: "upstream port range size (3) must match listen port range size (6)",
		},
		{
			name: "overlapping port ranges error",
			yaml: `
services:
  svc1:
    listen: ":8000-8005"
    upstream: "127.0.0.1:8080"
    protocol: "tcp"
  svc2:
    listen: ":8003-8008"
    upstream: "127.0.0.1:8080"
    protocol: "tcp"
`,
			wantErr: "duplicate listen address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestTCPAndUDPSamePortCoexistence(t *testing.T) {
	// TCP and UDP on the same port should not conflict
	validYAML := `
services:
  dns_tcp:
    transport: tcp
    listen: ":53"
    upstream: "1.1.1.1:53"
    protocol: "tcp"
  dns_udp:
    transport: udp
    listen: ":53"
    upstream: "1.1.1.1:53"
    protocol: "udp"
`
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("expected TCP and UDP on same port to coexist, got: %v", err)
	}
	if len(cfg.Warnings) > 0 {
		t.Errorf("unexpected warnings for built-in udp protocol: %v", cfg.Warnings)
	}

	// Two TCP services on the same port should conflict
	conflictYAML := `
services:
  dns1:
    transport: tcp
    listen: ":53"
    upstream: "1.1.1.1:53"
  dns2:
    transport: tcp
    listen: ":53"
    upstream: "8.8.8.8:53"
`
	_, err = Parse([]byte(conflictYAML))
	if err == nil || !strings.Contains(err.Error(), "duplicate listen address") {
		t.Fatalf("expected conflict on duplicate TCP port, got: %v", err)
	}
}

func TestResolveUpstreamUDPAddr(t *testing.T) {
	svc := ServiceConfig{
		Listen:   ":8000-8005",
		Upstream: "10.0.0.1:9000-9005",
	}
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8003}
	resolved, err := svc.ResolveUpstream(udpAddr)
	if err != nil {
		t.Fatalf("ResolveUpstream with UDPAddr failed: %v", err)
	}
	if resolved != "10.0.0.1:9003" {
		t.Errorf("expected 10.0.0.1:9003, got %q", resolved)
	}
}

// ── Bug #11 (Round 2): SocketMode.UnmarshalYAML must reject invalid octal input ──

func TestSocketMode_UnmarshalYAML_Valid(t *testing.T) {
	tests := []struct {
		yamlInput string
		expected  SocketMode
	}{
		{`mode: "0660"`, 0660},
		{`mode: "0600"`, 0600},
		{`mode: "0755"`, 0755},
		{`mode: 0660`, 0660},
	}

	for _, tc := range tests {
		var s struct {
			Mode SocketMode `yaml:"mode"`
		}
		if err := yaml.Unmarshal([]byte(tc.yamlInput), &s); err != nil {
			t.Errorf("unexpected error unmarshaling %q: %v", tc.yamlInput, err)
		}
		if s.Mode != tc.expected {
			t.Errorf("input %q: expected %o, got %o", tc.yamlInput, tc.expected, s.Mode)
		}
	}
}

func TestSocketMode_UnmarshalYAML_Invalid(t *testing.T) {
	invalidInputs := []string{
		`mode: "0abc"`,
		`mode: "999"`,
		`mode: "0888"`,
		`mode: "not-an-octal"`,
	}

	for _, in := range invalidInputs {
		var s struct {
			Mode SocketMode `yaml:"mode"`
		}
		err := yaml.Unmarshal([]byte(in), &s)
		if err == nil {
			t.Errorf("expected error unmarshaling invalid octal %q, but got nil (mode was %o)", in, s.Mode)
		}
	}
}

func TestIsValidIPOrCIDR_ZoneIndex(t *testing.T) {
	valid := []string{
		"192.168.1.1",
		"10.0.0.0/8",
		"2001:db8::1",
		"fe80::1%eth0",
		"fe80::1%1",
		"[2001:db8::1]",
		"[fe80::1%eth0]",
		"2001:db8::/32",
		"[2001:db8::]/32",
		"[2001:db8::1]/64",
	}
	for _, s := range valid {
		if !isValidIPOrCIDR(s) {
			t.Errorf("expected %q to be valid IP or CIDR", s)
		}
	}
}

func TestDuration_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{`"1h"`, 1 * time.Hour, false},
		{`"30m"`, 30 * time.Minute, false},
		{`"15s"`, 15 * time.Second, false},
		{`3600`, 3600 * time.Second, false},
		{`"1d"`, 24 * time.Hour, false},
		{`"7d"`, 7 * 24 * time.Hour, false},
		{`"30d"`, 30 * 24 * time.Hour, false},
		{`"1.5d"`, 36 * time.Hour, false},
		{`"invalid"`, 0, true},
	}

	for _, tc := range tests {
		var d Duration
		err := yaml.Unmarshal([]byte(tc.input), &d)
		if tc.wantErr {
			if err == nil {
				t.Errorf("expected error for input %s, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for input %s: %v", tc.input, err)
			}
			if d.Duration() != tc.expected {
				t.Errorf("input %s: expected %v, got %v", tc.input, tc.expected, d.Duration())
			}
		}
	}
}


