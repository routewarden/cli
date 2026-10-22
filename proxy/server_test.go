package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/routewarden/cli/proxy/config"
)

func TestServer_LifecycleAndReload(t *testing.T) {
	cfg := &config.Config{
		Global: config.GlobalConfig{
			LogLevel: "warn",
		},
		Services: map[string]config.ServiceConfig{
			"test_svc": {
				Listen:   "127.0.0.1:48123",
				Upstream: "127.0.0.1:48124",
				Protocol: "generic",
			},
		},
	}

	srv, err := NewServer(cfg, ServerOptions{
		Verbose: false,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if srv.Daemon() == nil {
		t.Fatal("expected non-nil daemon")
	}

	// Test Reload with nil config
	if err := srv.Reload(nil); err == nil {
		t.Error("expected error reloading nil config")
	}

	// Test Reload with updated log level
	newCfg := &config.Config{
		Global: config.GlobalConfig{
			LogLevel: "debug",
		},
		Services: cfg.Services,
	}
	if err := srv.Reload(newCfg); err != nil {
		t.Fatalf("failed to reload server: %v", err)
	}

	if srv.cfg.Global.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got %q", srv.cfg.Global.LogLevel)
	}

	// Test Start and Stop if live socket listening is permitted
	testL, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Logf("skipping live listener test: net.Listen restricted in test environment: %v", listenErr)
		return
	}
	testL.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Attempt second Start while running should fail
	if err := srv.Start(ctx); err == nil {
		t.Error("expected error starting already running server")
	}

	srv.Stop()
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("server exited with unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestServer_NilConfig(t *testing.T) {
	_, err := NewServer(nil, ServerOptions{})
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	confPath := tmpDir + "/auto-created.yaml"

	cfg, err := LoadConfig(confPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	// Calling LoadConfig with existing file
	cfg2, err := LoadConfig(confPath)
	if err != nil {
		t.Fatalf("LoadConfig secondary call failed: %v", err)
	}
	if cfg2 == nil {
		t.Fatal("expected non-nil config on second load")
	}
}
