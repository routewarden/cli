package engine_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routewarden/cli/engine"
)

func TestSandbox_GenerateSandboxConfig(t *testing.T) {
	cfg := engine.CreateConfig()
	cfg.PathPatterns = []string{"^/admin/.*$"}
	cfg.AllowPatterns = []string{"^/admin/public$"}
	cfg.AllowedIPs = []string{"192.168.1.10"}
	cfg.Methods = []string{"GET", "POST"}

	t.Run("traefik sandbox YAML", func(t *testing.T) {
		conf, err := engine.GenerateSandboxConfig("traefik", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(conf, "sandbox-router:") {
			t.Errorf("missing sandbox-router in traefik YAML:\n%s", conf)
		}
		if !strings.Contains(conf, "service: ping@internal") {
			t.Errorf("missing ping@internal service in traefik YAML:\n%s", conf)
		}
		if !strings.Contains(conf, "routewarden:") {
			t.Errorf("missing routewarden middleware in traefik YAML:\n%s", conf)
		}
		if !strings.Contains(conf, "^/admin/.*$") {
			t.Errorf("missing pathPattern in traefik YAML:\n%s", conf)
		}
	})

	t.Run("caddy sandbox Caddyfile", func(t *testing.T) {
		conf, err := engine.GenerateSandboxConfig("caddy", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(conf, ":8080 {") {
			t.Errorf("missing :8080 block in Caddyfile:\n%s", conf)
		}
		if !strings.Contains(conf, "order routewarden first") {
			t.Errorf("missing order routewarden first in Caddyfile:\n%s", conf)
		}
		if !strings.Contains(conf, "routewarden {") {
			t.Errorf("missing routewarden block in Caddyfile:\n%s", conf)
		}
		if !strings.Contains(conf, "respond \"OK: Upstream Passed (RouteWarden Sandbox)\" 200") {
			t.Errorf("missing mock upstream respond in Caddyfile:\n%s", conf)
		}
	})

	t.Run("nginx sandbox nginx.conf", func(t *testing.T) {
		conf, err := engine.GenerateSandboxConfig("nginx", cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(conf, "worker_processes") {
			t.Errorf("missing worker_processes in nginx.conf:\n%s", conf)
		}
		if !strings.Contains(conf, "init_by_lua_block {") {
			t.Errorf("missing init_by_lua_block in nginx.conf:\n%s", conf)
		}
		if !strings.Contains(conf, "warden_instance = routewarden.new(routewarden_config)") {
			t.Errorf("missing warden_instance init in nginx.conf:\n%s", conf)
		}
		if !strings.Contains(conf, "access_by_lua_block {") {
			t.Errorf("missing access_by_lua_block in nginx.conf:\n%s", conf)
		}
		if !strings.Contains(conf, "OK: Upstream Passed (RouteWarden Sandbox)") {
			t.Errorf("missing mock upstream output in nginx.conf:\n%s", conf)
		}
	})

	t.Run("nil config defaults gracefully", func(t *testing.T) {
		conf, err := engine.GenerateSandboxConfig("traefik", nil)
		if err != nil {
			t.Fatalf("unexpected error for nil config: %v", err)
		}
		if !strings.Contains(conf, "sandbox-router:") {
			t.Errorf("expected generated router for nil config")
		}
	})

	t.Run("invalid target returns error", func(t *testing.T) {
		_, err := engine.GenerateSandboxConfig("unknown-gateway", cfg)
		if err == nil {
			t.Fatalf("expected error for unsupported target")
		}
	})
}

func TestSandbox_BuildDockerRunCommand(t *testing.T) {
	t.Run("traefik default command", func(t *testing.T) {
		opts := engine.SandboxOptions{
			Target: "traefik",
			Port:   8080,
		}
		img, args := engine.BuildDockerRunCommand(opts, "/tmp/dynamic.yml", "test-traefik")
		if img != "traefik:v3.3" {
			t.Errorf("expected traefik:v3.3, got %s", img)
		}
		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, "--name test-traefik") {
			t.Errorf("missing container name in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "-p 8080:8080") {
			t.Errorf("missing port mapping in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, ":/etc/traefik:ro") {
			t.Errorf("missing dynamic.yml volume mount in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "--providers.file.filename=/etc/traefik/dynamic.yml") {
			t.Errorf("missing provider filename in: %s", cmdStr)
		}
	})

	t.Run("traefik TOML format mounts dynamic.toml", func(t *testing.T) {
		opts := engine.SandboxOptions{
			Target: "traefik",
			Format: engine.FormatTraefikTOML,
			Port:   9000,
		}
		_, args := engine.BuildDockerRunCommand(opts, "/tmp/dynamic.toml", "test-traefik-toml")
		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, ":/etc/traefik:ro") {
			t.Errorf("missing dynamic.toml mount in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "--providers.file.filename=/etc/traefik/dynamic.toml") {
			t.Errorf("missing provider filename dynamic.toml in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "-p 9000:8080") {
			t.Errorf("missing custom port mapping in: %s", cmdStr)
		}
	})

	t.Run("traefik local plugin path and version override", func(t *testing.T) {
		opts := engine.SandboxOptions{
			Target:        "traefik",
			PluginVersion: "v1.2.0",
			Version:       "v3.2",
			Detach:        true,
		}
		img, args := engine.BuildDockerRunCommand(opts, "/tmp/dynamic.yml", "test-traefik-plugin")
		if img != "traefik:v3.2" {
			t.Errorf("expected version tag override traefik:v3.2, got %s", img)
		}
		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, "-d") {
			t.Errorf("missing -d detach flag in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "--experimental.plugins.routewarden.version=v1.2.0") {
			t.Errorf("missing experimental plugin version flag in: %s", cmdStr)
		}
	})

	t.Run("traefik local plugin directory mount", func(t *testing.T) {
		tmpDir := t.TempDir()
		opts := engine.SandboxOptions{
			Target:     "traefik",
			PluginPath: tmpDir,
		}
		_, args := engine.BuildDockerRunCommand(opts, "/tmp/dynamic.yml", "test-traefik-local")
		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, ":/plugins-local/src/github.com/routewarden/traefik-warden:ro") {
			t.Errorf("missing local plugin mount in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "--experimental.localplugins.routewarden.modulename=github.com/routewarden/traefik-warden") {
			t.Errorf("missing localplugins modulename in: %s", cmdStr)
		}
	})

	t.Run("caddy default and plugin version image", func(t *testing.T) {
		opts := engine.SandboxOptions{
			Target: "caddy",
			Port:   8080,
		}
		img, args := engine.BuildDockerRunCommand(opts, "/tmp/Caddyfile", "test-caddy")
		if img != "ghcr.io/routewarden/caddy-warden:latest" {
			t.Errorf("expected default caddy image, got %s", img)
		}
		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, "-v /tmp/Caddyfile:/etc/caddy/Caddyfile:ro") {
			t.Errorf("missing Caddyfile mount in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "caddy run --config /etc/caddy/Caddyfile --adapter caddyfile") {
			t.Errorf("missing caddy run arguments in: %s", cmdStr)
		}

		// With plugin version
		optsPlugin := engine.SandboxOptions{
			Target:        "caddy",
			PluginVersion: "v1.0.5",
		}
		imgPlugin, _ := engine.BuildDockerRunCommand(optsPlugin, "/tmp/Caddyfile", "test-caddy-plugin")
		if imgPlugin != "ghcr.io/routewarden/caddy-warden:v1.0.5" {
			t.Errorf("expected ghcr.io/routewarden/caddy-warden:v1.0.5, got %s", imgPlugin)
		}
	})

	t.Run("nginx default and local plugin mount", func(t *testing.T) {
		tmpDir := t.TempDir()
		opts := engine.SandboxOptions{
			Target:     "nginx",
			PluginPath: tmpDir,
		}
		img, args := engine.BuildDockerRunCommand(opts, "/tmp/nginx.conf", "test-nginx")
		if img != "openresty/openresty:alpine" {
			t.Errorf("expected default nginx image, got %s", img)
		}
		cmdStr := strings.Join(args, " ")
		if !strings.Contains(cmdStr, "-v /tmp/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro") {
			t.Errorf("missing nginx.conf mount in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, ":/usr/local/openresty/site/lualib/resty/routewarden:ro") {
			t.Errorf("missing local lua mount in: %s", cmdStr)
		}
		if !strings.Contains(cmdStr, "/usr/local/openresty/bin/openresty -g daemon off;") {
			t.Errorf("missing openresty execution command in: %s", cmdStr)
		}

		// With plugin version
		optsPlugin := engine.SandboxOptions{
			Target:        "nginx",
			PluginVersion: "v1.1.0",
		}
		imgPlugin, _ := engine.BuildDockerRunCommand(optsPlugin, "/tmp/nginx.conf", "test-nginx-plugin")
		if imgPlugin != "ghcr.io/routewarden/nginx-warden:v1.1.0" {
			t.Errorf("expected ghcr.io/routewarden/nginx-warden:v1.1.0, got %s", imgPlugin)
		}
	})

	t.Run("custom image override", func(t *testing.T) {
		opts := engine.SandboxOptions{
			Target: "caddy",
			Image:  "my-registry.local/custom-caddy:debug",
		}
		img, _ := engine.BuildDockerRunCommand(opts, "/tmp/Caddyfile", "test-custom")
		if img != "my-registry.local/custom-caddy:debug" {
			t.Errorf("expected custom image override, got %s", img)
		}
	})
}

func TestSandbox_PrepareActualGatewayConfig(t *testing.T) {
	t.Run("traefik toml middleware snippet wrapping", func(t *testing.T) {
		snippet := `[http.middlewares.shield.plugin.routewarden]
  enabled = true
`
		wrapped := engine.PrepareActualGatewayConfig("traefik", engine.FormatTraefikTOML, snippet)
		if !strings.Contains(wrapped, "[http.routers.sandbox-router]") {
			t.Errorf("missing sandbox-router in wrapped TOML:\n%s", wrapped)
		}
		if !strings.Contains(wrapped, `service = "ping@internal"`) {
			t.Errorf("missing ping@internal in wrapped TOML:\n%s", wrapped)
		}
		if !strings.Contains(wrapped, "middlewares.shield.plugin.routewarden") {
			t.Errorf("original snippet lost in wrapped TOML:\n%s", wrapped)
		}

		// When already has router, don't wrap
		fullToml := `[http.routers.app]
rule = "Host('localhost')"
`
		unwrapped := engine.PrepareActualGatewayConfig("traefik", engine.FormatTraefikTOML, fullToml)
		if unwrapped != strings.TrimSpace(fullToml) {
			t.Errorf("full TOML should not be modified, got:\n%s", unwrapped)
		}
	})

	t.Run("traefik yaml middleware snippet wrapping", func(t *testing.T) {
		snippet := `middlewares:
  shield:
    plugin:
      routewarden:
        enabled: true
`
		wrapped := engine.PrepareActualGatewayConfig("traefik", engine.FormatTraefikYAML, snippet)
		if !strings.Contains(wrapped, "sandbox-router:") {
			t.Errorf("missing sandbox-router in wrapped YAML:\n%s", wrapped)
		}
		if !strings.Contains(wrapped, "service: ping@internal") {
			t.Errorf("missing ping@internal in wrapped YAML:\n%s", wrapped)
		}

		// When already has router, don't wrap
		fullYaml := `http:
  routers:
    app: {}
`
		unwrapped := engine.PrepareActualGatewayConfig("traefik", engine.FormatTraefikYAML, fullYaml)
		if unwrapped != strings.TrimSpace(fullYaml) {
			t.Errorf("full YAML should not be modified, got:\n%s", unwrapped)
		}
	})

	t.Run("caddy snippet wrapping", func(t *testing.T) {
		snippet := `routewarden {
    methods GET
}`
		wrapped := engine.PrepareActualGatewayConfig("caddy", engine.FormatCaddyfile, snippet)
		if !strings.Contains(wrapped, ":8080 {") {
			t.Errorf("missing :8080 block in wrapped Caddyfile:\n%s", wrapped)
		}
		if !strings.Contains(wrapped, "respond \"OK: Upstream Passed (RouteWarden Sandbox)\" 200") {
			t.Errorf("missing mock respond in wrapped Caddyfile:\n%s", wrapped)
		}

		// Complete Caddyfile with :8080 not re-wrapped
		fullCaddy := `:8080 {
    respond 200
}`
		unwrapped := engine.PrepareActualGatewayConfig("caddy", engine.FormatCaddyfile, fullCaddy)
		if unwrapped != strings.TrimSpace(fullCaddy) {
			t.Errorf("complete Caddyfile should not be wrapped, got:\n%s", unwrapped)
		}
	})

	t.Run("nginx snippet wrapping", func(t *testing.T) {
		snippet := `access_by_lua_block { require("resty.routewarden") }`
		wrapped := engine.PrepareActualGatewayConfig("nginx", engine.FormatNginx, snippet)
		if !strings.Contains(wrapped, "worker_processes 1;") {
			t.Errorf("missing worker_processes in wrapped nginx.conf:\n%s", wrapped)
		}
		if !strings.Contains(wrapped, "listen 8080;") {
			t.Errorf("missing listen 8080 in wrapped nginx.conf:\n%s", wrapped)
		}

		// Complete nginx.conf not re-wrapped
		fullNginx := `worker_processes 1;
http {
    server { listen 8080; }
}`
		unwrapped := engine.PrepareActualGatewayConfig("nginx", engine.FormatNginx, fullNginx)
		if unwrapped != strings.TrimSpace(fullNginx) {
			t.Errorf("complete nginx.conf should not be wrapped, got:\n%s", unwrapped)
		}
	})
}

func TestSandbox_PrepareSandboxTempFileWithFormat(t *testing.T) {
	tests := []struct {
		target       string
		format       engine.ConfigFormat
		content      string
		wantFilename string
	}{
		{target: "traefik", format: engine.FormatTraefikTOML, content: "test", wantFilename: "dynamic.toml"},
		{target: "traefik-toml", format: engine.FormatUnknown, content: "test", wantFilename: "dynamic.toml"},
		{target: "traefik", format: engine.FormatTraefikYAML, content: "test", wantFilename: "dynamic.yml"},
		{target: "caddy", format: engine.FormatCaddyfile, content: "test", wantFilename: "Caddyfile"},
		{target: "nginx", format: engine.FormatNginx, content: "test", wantFilename: "nginx.conf"},
		{target: "custom", format: engine.FormatUnknown, content: "test", wantFilename: "routewarden.conf"},
	}

	for _, tc := range tests {
		filePath, cleanup, err := engine.PrepareSandboxTempFileWithFormat(tc.target, tc.content, tc.format)
		if err != nil {
			t.Fatalf("[%s/%s] unexpected error: %v", tc.target, tc.format, err)
		}
		base := filepath.Base(filePath)
		if base != tc.wantFilename {
			t.Errorf("expected filename %q, got %q", tc.wantFilename, base)
		}
		data, err := os.ReadFile(filePath)
		if err != nil || string(data) != tc.content {
			t.Errorf("file content mismatch: got %q, want %q", string(data), tc.content)
		}
		cleanup()
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Errorf("file should have been cleaned up after cleanup() call")
		}
	}
}

func TestSandbox_LiveProbeTest_MockServer(t *testing.T) {
	// In some restricted sandbox environments, binding local sockets is disabled.
	// We test IPv4 loopback binding and skip if network socket creation is disallowed.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping live HTTP test in sandbox environment without local socket permissions: %v", err)
		return
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// IP bypass test
		if r.Header.Get("X-Forwarded-For") == "10.0.0.1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Allowed by IP"))
			return
		}

		// Direct sensitive paths, raw request URI traversal (%252e%252e), or query/header evasion
		rawURI := r.RequestURI
		if r.URL.Path == "/.env" || strings.Contains(r.URL.Path, "..") ||
			strings.Contains(rawURI, "%252e") || strings.Contains(rawURI, "%2e") || strings.Contains(rawURI, "..") ||
			r.Header.Get("X-Forwarded-Uri") == "/.env" || r.URL.Path == "/custom/sensitive" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Blocked by RouteWarden"))
			return
		}

		// Public endpoint
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *"))
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	// Extract port from ts.URL
	parts := strings.Split(ts.URL, ":")
	portStr := parts[len(parts)-1]
	var port int
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}

	// Run LiveProbeTestWithOptions with custom probe path and probe IP
	passed, total, summary := engine.LiveProbeTestWithOptions(port, 403, []string{"/custom/sensitive"}, "10.0.0.1")
	if passed != total {
		t.Fatalf("expected all %d probe tests to pass, got %d passed. Output:\n%s", total, passed, summary)
	}
	if !strings.Contains(summary, "Direct sensitive file block (/.env)") {
		t.Errorf("missing direct sensitive test in summary:\n%s", summary)
	}
	if !strings.Contains(summary, "Custom probe path (/custom/sensitive)") {
		t.Errorf("missing custom probe path in summary:\n%s", summary)
	}
	if !strings.Contains(summary, "Allowed IP bypass (X-Forwarded-For: 10.0.0.1)") {
		t.Errorf("missing IP allowlist bypass test in summary:\n%s", summary)
	}
}

func TestSandbox_ReadConfigContent(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.conf")
	expected := "sample configuration content"
	if err := os.WriteFile(cfgFile, []byte(expected), 0644); err != nil {
		t.Fatal(err)
	}

	data, err := engine.ReadConfigContent(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error reading file: %v", err)
	}
	if string(data) != expected {
		t.Fatalf("got %q, want %q", string(data), expected)
	}
}
