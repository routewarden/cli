package sdk_test

import (
	"testing"

	"github.com/routewarden/cli/proxy/plugins/sdk"
)

func TestManifest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		m       sdk.Manifest
		wantErr bool
	}{
		{
			name: "valid manifest",
			m: sdk.Manifest{
				Name:      "test_plugin",
				Version:   "1.0.0",
				Protocols: []string{"tcp"},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			m: sdk.Manifest{
				Version:   "1.0.0",
				Protocols: []string{"tcp"},
			},
			wantErr: true,
		},
		{
			name: "missing version",
			m: sdk.Manifest{
				Name:      "test_plugin",
				Protocols: []string{"tcp"},
			},
			wantErr: true,
		},
		{
			name: "missing protocols",
			m: sdk.Manifest{
				Name:    "test_plugin",
				Version: "1.0.0",
			},
			wantErr: true,
		},
		{
			name: "path traversal in name",
			m: sdk.Manifest{
				Name:      "../evil",
				Version:   "1.0.0",
				Protocols: []string{"tcp"},
			},
			wantErr: true,
		},
		{
			name: "slash in name",
			m: sdk.Manifest{
				Name:      "evil/plugin",
				Version:   "1.0.0",
				Protocols: []string{"tcp"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.m.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestManifest_CheckCompatibility(t *testing.T) {
	tests := []struct {
		name        string
		manifestVer string
		hostVer     string
		wantErr     bool
	}{
		{
			name:        "empty manifest version is accepted",
			manifestVer: "",
			hostVer:     "1.0.5",
			wantErr:     false,
		},
		{
			name:        "same major and lower/equal minor is compatible",
			manifestVer: "1.0.0",
			hostVer:     "1.0.5",
			wantErr:     false,
		},
		{
			name:        "different major is incompatible",
			manifestVer: "2.0.0",
			hostVer:     "1.0.5",
			wantErr:     true,
		},
		{
			name:        "higher minor is incompatible",
			manifestVer: "1.2.0",
			hostVer:     "1.0.5",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := sdk.Manifest{
				Name:            "test",
				Version:         "1.0.0",
				Protocols:       []string{"tcp"},
				ManifestVersion: tt.manifestVer,
			}
			err := m.CheckCompatibility(tt.hostVer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckCompatibility() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseManifest(t *testing.T) {
	yamlData := []byte(`
name: postgres_filter
version: 1.2.0
description: PostgreSQL protocol filter
author: RouteWarden
protocols:
  - postgres
  - pgsql
manifest_version: 1.0.0
`)

	m, err := sdk.ParseManifest(yamlData)
	if err != nil {
		t.Fatalf("ParseManifest failed: %v", err)
	}

	if m.Name != "postgres_filter" {
		t.Errorf("expected Name postgres_filter, got %s", m.Name)
	}
	if len(m.Protocols) != 2 {
		t.Errorf("expected 2 protocols, got %d", len(m.Protocols))
	}
}

func TestMustParseManifest_PanicOnInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on invalid manifest, got none")
		}
	}()

	invalidYAML := []byte(`name: missing_protocols_and_version`)
	sdk.MustParseManifest(invalidYAML)
}

func TestMustParseManifest_Success(t *testing.T) {
	validYAML := []byte(`
name: redis_filter
version: 1.0.0
protocols:
  - redis
`)
	m := sdk.MustParseManifest(validYAML)
	if m.Name != "redis_filter" {
		t.Errorf("expected Name redis_filter, got %s", m.Name)
	}
}

func TestDefaultContext(t *testing.T) {
	authFailed := false
	var secAction, secReason string

	ctx := &sdk.DefaultContext{
		ServiceName:   "ssh",
		ClientAddress: "192.0.2.1",
		AuthFailureFunc: func() {
			authFailed = true
		},
		SecurityFunc: func(action, reason string) {
			secAction = action
			secReason = reason
		},
	}

	if ctx.Service() != "ssh" {
		t.Errorf("expected service ssh, got %s", ctx.Service())
	}
	if ctx.ClientIP() != "192.0.2.1" {
		t.Errorf("expected client IP 192.0.2.1, got %s", ctx.ClientIP())
	}
	if ctx.Context() == nil {
		t.Error("expected non-nil context")
	}

	ctx.OnAuthFailure()
	if !authFailed {
		t.Error("expected authFailed to be true")
	}

	ctx.OnSecurityEvent("block", "pattern_match")
	if secAction != "block" || secReason != "pattern_match" {
		t.Errorf("expected block / pattern_match, got %s / %s", secAction, secReason)
	}
}
