package plugins_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/routewarden/cli/proxy/plugins"
	"github.com/routewarden/cli/proxy/plugins/sdk"
)

type dummyHealthyPlugin struct{}

func (d *dummyHealthyPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "healthy-plugin",
		Version:     "1.0.0",
		Description: "A test healthy plugin",
		Protocols:   []string{"healthy-proto"},
	}
}

func (d *dummyHealthyPlugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (d *dummyHealthyPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return nil, nil
}

func (d *dummyHealthyPlugin) SelfTest() error {
	return nil
}

type dummyFaultyPlugin struct{}

func (d *dummyFaultyPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "faulty-plugin",
		Version:     "1.0.0",
		Description: "A plugin that deliberately fails its self-test",
		Protocols:   []string{"faulty-proto"},
	}
}

func (d *dummyFaultyPlugin) ValidateConfig(config map[string]any) error {
	return nil
}

func (d *dummyFaultyPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return nil, nil
}

func (d *dummyFaultyPlugin) SelfTest() error {
	return errors.New("synthetic self-test failure: handshake assertion failed")
}

func TestPluginRegistry_SelfTestingAndAutoDisable(t *testing.T) {
	reg := plugins.NewRegistry()

	healthy := &dummyHealthyPlugin{}
	faulty := &dummyFaultyPlugin{}

	reg.Register(healthy)
	reg.Register(faulty)

	// Before enabling, status should be DISABLED (disabled by default)
	st, reason, _ := reg.GetStatus("healthy-plugin")
	if st != plugins.StatusDisabled || reason != "disabled by default" {
		t.Fatalf("expected DISABLED by default, got %v (%s)", st, reason)
	}

	// Explicitly enable healthy plugin (runs self-test)
	if err := reg.Enable("healthy-plugin"); err != nil {
		t.Fatalf("expected healthy-plugin to enable successfully: %v", err)
	}
	if !reg.IsActive("healthy-plugin") {
		t.Errorf("healthy-plugin should be active after enable")
	}

	// Attempting to enable faulty plugin should return error and remain disabled
	if err := reg.Enable("faulty-plugin"); err == nil {
		t.Errorf("expected enable faulty-plugin to return error")
	}
	if reg.IsActive("faulty-plugin") {
		t.Errorf("faulty-plugin should NOT be active")
	}

	status, reason, err := reg.GetStatus("faulty-proto")
	if status != plugins.StatusDisabled {
		t.Errorf("expected StatusDisabled, got %v", status)
	}
	if reason != "self-test failed" {
		t.Errorf("expected reason self-test failed, got %s", reason)
	}
	if err == nil || err.Error() != "synthetic self-test failure: handshake assertion failed" {
		t.Errorf("unexpected error: %v", err)
	}

	// Test Disable
	if err := reg.Disable("healthy-plugin", "admin disabled"); err != nil {
		t.Fatal(err)
	}
	if reg.IsActive("healthy-plugin") {
		t.Errorf("healthy-plugin should be inactive after disable")
	}

	// Verify List
	list := reg.List()
	if len(list) != 2 {
		t.Errorf("expected 2 plugins in list, got %d", len(list))
	}
}

func TestSDK_DefaultContext(t *testing.T) {
	authFailed := false
	secAction := ""
	secReason := ""

	ctx := &sdk.DefaultContext{
		ServiceName:   "test-svc",
		ClientAddress: "192.0.2.1",
		AuthFailureFunc: func() {
			authFailed = true
		},
		SecurityFunc: func(action, reason string) {
			secAction = action
			secReason = reason
		},
	}

	if ctx.Service() != "test-svc" {
		t.Errorf("expected test-svc, got %s", ctx.Service())
	}
	if ctx.ClientIP() != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1, got %s", ctx.ClientIP())
	}

	ctx.OnAuthFailure()
	if !authFailed {
		t.Errorf("expected authFailed to be true")
	}

	ctx.OnSecurityEvent("blocked", "bad_packet")
	if secAction != "blocked" || secReason != "bad_packet" {
		t.Errorf("expected security event recorded")
	}

	p1, p2 := net.Pipe()
	p1.Close()
	p2.Close()
}

func TestParseManifest(t *testing.T) {
	yamlContent := `
name: test_embed
version: 1.2.3
manifest_version: 1.0.0
description: Embedded manifest test
author: Test Author
protocols:
  - test_proto
`
	m := sdk.MustParseManifest([]byte(yamlContent))
	if m.Name != "test_embed" {
		t.Errorf("expected name test_embed, got %s", m.Name)
	}
	if m.Version != "1.2.3" {
		t.Errorf("expected version 1.2.3, got %s", m.Version)
	}
	if m.ManifestVersion != "1.0.0" {
		t.Errorf("expected manifest_version 1.0.0, got %s", m.ManifestVersion)
	}
	if len(m.Protocols) != 1 || m.Protocols[0] != "test_proto" {
		t.Errorf("unexpected protocols: %v", m.Protocols)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.2.0", "1.1.0", 1},
		{"1.1.0", "1.2.0", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.0", "1.0.0", 0},
		{"1.2.0-beta.1", "1.2.0", -1},
		{"1.2.0", "1.2.0-rc.1", 1},
		{"1.2.0-alpha", "1.2.0-beta", -1},
	}

	for _, tt := range tests {
		got := plugins.CompareVersions(tt.v1, tt.v2)
		if got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
		}
	}
}

type mockIncompatiblePlugin struct{}

func (m *mockIncompatiblePlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:            "future-plugin",
		Version:         "1.0.0",
		Protocols:       []string{"future-proto"},
		ManifestVersion: "99.0.0", // incompatible with current manifest version
	}
}
func (m *mockIncompatiblePlugin) ValidateConfig(map[string]any) error { return nil }
func (m *mockIncompatiblePlugin) CreateInspector(map[string]any) (sdk.Inspector, error) {
	return nil, nil
}
func (m *mockIncompatiblePlugin) SelfTest() error { return nil }

func TestPluginCompatibilityAndAutoDisable(t *testing.T) {
	reg := plugins.NewRegistry()
	incompat := &mockIncompatiblePlugin{}

	// Registering an incompatible plugin should mark it as INCOMPATIBLE and DISABLED
	reg.Register(incompat)

	status, reason, _ := reg.GetStatus("future-plugin")
	if status != plugins.StatusIncompatible {
		t.Errorf("expected StatusIncompatible, got %s", status)
	}
	if !strings.Contains(reason, "incompatible manifest version") {
		t.Errorf("expected reason to contain 'incompatible manifest version', got %s", reason)
	}

	// Attempting to enable it must fail and keep it disabled
	if err := reg.Enable("future-plugin"); err == nil {
		t.Fatalf("expected enabling incompatible plugin to fail, got nil")
	}
	if reg.IsActive("future-plugin") {
		t.Errorf("expected future-plugin to remain inactive")
	}
}

type dummyPanickingSelfTestPlugin struct{}

func (d *dummyPanickingSelfTestPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "panic-plugin",
		Version:     "1.0.0",
		Description: "A plugin that deliberately panics during self-test",
		Protocols:   []string{"panic-proto"},
	}
}
func (d *dummyPanickingSelfTestPlugin) ValidateConfig(config map[string]any) error { return nil }
func (d *dummyPanickingSelfTestPlugin) CreateInspector(config map[string]any) (sdk.Inspector, error) {
	return nil, nil
}
func (d *dummyPanickingSelfTestPlugin) SelfTest() error {
	panic("fatal synthetic self-test crash")
}

func TestPluginRegistry_SelfTestPanicRecovery(t *testing.T) {
	reg := plugins.NewRegistry()
	reg.Register(&dummyPanickingSelfTestPlugin{})

	// Enable should recover from panic and return an informative error
	err := reg.Enable("panic-plugin")
	if err == nil {
		t.Fatal("expected Enable to fail when self-test panics, got nil")
	}
	if !strings.Contains(err.Error(), "panicked during self-test") {
		t.Errorf("expected error message to mention panic, got %v", err)
	}

	// Status should be disabled
	status, reason, _ := reg.GetStatus("panic-plugin")
	if status != plugins.StatusDisabled {
		t.Errorf("expected StatusDisabled, got %s", status)
	}
	if reason != "self-test failed" {
		t.Errorf("expected 'self-test failed', got %s", reason)
	}
}

