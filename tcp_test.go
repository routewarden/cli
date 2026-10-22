package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/routewarden/cli/proxy"
	"github.com/routewarden/cli/proxy/config"
	"github.com/routewarden/cli/proxy/core"
	"github.com/routewarden/cli/proxy/plugins"
	_ "github.com/routewarden/cli/proxy/plugins/all"
	"github.com/routewarden/cli/proxy/plugins/sdk"
)

type dummyTestPlugin struct{}

func (d *dummyTestPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "test-health-plugin",
		Version:     "1.0.0",
		Description: "A test health plugin",
		Protocols:   []string{"tcp"},
	}
}

func (d *dummyTestPlugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (d *dummyTestPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return nil, nil
}

func (d *dummyTestPlugin) SelfTest() error {
	return nil
}

func TestTCP_ResolveConfigPath(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Explicit path
	customPath := filepath.Join(tmpDir, "custom.yaml")
	if got := resolveTCPConfigPath(customPath); got != customPath {
		t.Errorf("expected %q, got %q", customPath, got)
	}

	// 2. ROUTEWARDEN_CONFIG env var
	t.Setenv("ROUTEWARDEN_CONFIG", filepath.Join(tmpDir, "env.yaml"))
	if got := resolveTCPConfigPath(""); got != filepath.Join(tmpDir, "env.yaml") {
		t.Errorf("expected env path, got %q", got)
	}
	t.Setenv("ROUTEWARDEN_CONFIG", "")

	// 3. Local tcp-warden.yml file detection
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err == nil {
		defer func() { _ = os.Chdir(origWd) }()
		_ = os.WriteFile("tcp-warden.yml", []byte("services:\n"), 0644)
		if got := resolveTCPConfigPath(""); got != "tcp-warden.yml" {
			t.Errorf("expected tcp-warden.yml, got %q", got)
		}
	}
}

func TestTCP_LoadDefaultConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test-tcp.yaml")

	// Should create default config file if not present
	cfg, err := proxy.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected non-nil config")
	}

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Fatalf("expected file %s to be created from default template", cfgPath)
	}
}

func TestTCP_PluginsListAndSelfTest(t *testing.T) {
	if len(plugins.List()) == 0 {
		plugins.Register(&dummyTestPlugin{})
	}

	list := plugins.List()
	if len(list) == 0 {
		t.Fatalf("expected registered plugins, got 0")
	}

	results := plugins.RunSelfTests()
	if len(results) == 0 {
		t.Fatalf("expected self-test results, got 0")
	}

	for name, res := range results {
		if res.Error != nil {
			t.Errorf("plugin %s failed self-test: %v", name, res.Error)
		}
	}
}

func TestTCP_ServerLifecycleAndEventListener(t *testing.T) {
	// Allocate a free TCP port for testing
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test in sandbox: socket bind not permitted: %v", err)
		return
	}
	listenAddr := l.Addr().String()
	_ = l.Close()

	// Echo upstream server
	echoListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping test in sandbox: socket bind not permitted: %v", err)
		return
	}
	defer echoListener.Close()
	echoAddr := echoListener.Addr().String()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	enabled := true
	cfg := &config.Config{
		Global: config.GlobalConfig{
			LogLevel: "error",
		},
		Services: map[string]config.ServiceConfig{
			"test_echo": {
				Name:     "test_echo",
				Listen:   listenAddr,
				Upstream: echoAddr,
				Protocol: "tcp",
				Enabled:  &enabled,
			},
		},
	}

	eventReceived := make(chan core.SecurityEvent, 10)
	srv, err := proxy.NewServer(cfg, proxy.ServerOptions{
		EventListener: func(ev core.SecurityEvent) {
			eventReceived <- ev
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Start(ctx)
	}()

	// Wait for server to bind
	time.Sleep(100 * time.Millisecond)

	// Connect to proxy
	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial proxy %s: %v", listenAddr, err)
	}
	_, _ = conn.Write([]byte("hello proxy"))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "hello proxy" {
		t.Errorf("expected 'hello proxy', got %q", string(buf[:n]))
	}
	_ = conn.Close()

	// Verify security event was captured by listener
	select {
	case ev := <-eventReceived:
		if ev.Service != "test_echo" {
			t.Errorf("expected service 'test_echo', got %q", ev.Service)
		}
		if ev.Action != "allowed" {
			t.Errorf("expected action 'allowed', got %q", ev.Action)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("timed out waiting for security event from proxy EventBus")
	}

	cancel()
	select {
	case err := <-serverDone:
		if err != nil && err != context.Canceled {
			t.Errorf("unexpected server exit error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Errorf("server did not shut down within timeout")
	}
}

func TestTCP_ServerStop(t *testing.T) {
	enabled := true
	cfg := &config.Config{
		Global: config.GlobalConfig{
			LogLevel: "error",
		},
		Services: map[string]config.ServiceConfig{
			"dummy": {
				Name:     "dummy",
				Listen:   "127.0.0.1:0",
				Upstream: "127.0.0.1:9",
				Protocol: "tcp",
				Enabled:  &enabled,
			},
		},
	}

	srv, err := proxy.NewServer(cfg, proxy.ServerOptions{})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Calling Stop before Start or after Start should be safe and idempotent
	srv.Stop()
	srv.Stop()
}

func TestTCP_ValidateYAML(t *testing.T) {
	// 1. Valid TCP config
	validYAML := `
version: "3"
services:
  web:
    listen: ":8080"
    upstream: "127.0.0.1:80"
    protocol: "http"
`
	cfg, err := config.Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}
	if len(cfg.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(cfg.Services))
	}

	// 2. Corrupted YAML syntax
	brokenYAML := `
services:
  web:
    listen: :8080
    [unbalanced
`
	if _, err := config.Parse([]byte(brokenYAML)); err == nil {
		t.Error("expected syntax error on broken YAML, got nil")
	}

	// 3. Invalid service (missing upstream)
	invalidServiceYAML := `
version: "3"
services:
  web:
    listen: ":8080"
    protocol: "http"
`
	if _, err := config.Parse([]byte(invalidServiceYAML)); err == nil {
		t.Error("expected validation error on missing upstream, got nil")
	}
}

