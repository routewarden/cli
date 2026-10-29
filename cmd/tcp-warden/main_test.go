package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTCPWarden_PrintUsage(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printUsage()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "TCP Warden") {
		t.Errorf("expected header in tcp-warden printUsage, got: %s", output)
	}
	if !strings.Contains(output, "run") || !strings.Contains(output, "validate") || !strings.Contains(output, "plugins") {
		t.Errorf("expected commands in usage, got: %s", output)
	}
}

func TestTCPWarden_ResolveConfigPath(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Explicit path
	explicit := filepath.Join(tmpDir, "my-conf.yaml")
	if got := resolveConfigPath(explicit); got != explicit {
		t.Errorf("expected %q, got %q", explicit, got)
	}

	// 2. ROUTEWARDEN_CONFIG env var
	t.Setenv("ROUTEWARDEN_CONFIG", filepath.Join(tmpDir, "env-conf.yaml"))
	if got := resolveConfigPath(""); got != filepath.Join(tmpDir, "env-conf.yaml") {
		t.Errorf("expected env path, got %q", got)
	}
	t.Setenv("ROUTEWARDEN_CONFIG", "")

	// 3. Local tcp-warden.yml file detection
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err == nil {
		defer func() { _ = os.Chdir(origWd) }()
		_ = os.WriteFile("tcp-warden.yml", []byte("services:\n"), 0644)
		if got := resolveConfigPath(""); got != "tcp-warden.yml" {
			t.Errorf("expected tcp-warden.yml, got %q", got)
		}
	}
}

func TestTCPWarden_EnsureConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "sub", "tcp-warden.yaml")

	// Ensure creates default template
	if err := ensureConfigFile(targetPath); err != nil {
		t.Fatalf("ensureConfigFile failed: %v", err)
	}

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		t.Errorf("expected %s to exist", targetPath)
	}

	// Calling again should not error or overwrite
	if err := ensureConfigFile(targetPath); err != nil {
		t.Fatalf("ensureConfigFile secondary call failed: %v", err)
	}
}

func TestTCPWarden_Truncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"hello", 1, "…"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hell…"},
		{"✓ unicode test", 9, "✓ unicod…"},
	}
	for _, tc := range tests {
		got := truncate(tc.input, tc.maxLen)
		if got != tc.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
		}
	}
}

func TestTCPWarden_NormalizeArgs(t *testing.T) {
	// Flags before positionals
	args1 := []string{"--config", "conf.yaml", "validate"}
	norm1 := normalizeArgs(args1)
	if len(norm1) != 3 || norm1[0] != "--config" || norm1[1] != "conf.yaml" || norm1[2] != "validate" {
		t.Errorf("unexpected norm1: %v", norm1)
	}

	// Positionals before flags
	args2 := []string{"ban", "1.2.3.4", "--duration", "2h"}
	norm2 := normalizeArgs(args2)
	if len(norm2) != 4 || norm2[0] != "--duration" || norm2[1] != "2h" || norm2[2] != "ban" || norm2[3] != "1.2.3.4" {
		t.Errorf("unexpected norm2: %v", norm2)
	}

	// Boolean flag without consuming next arg
	args3 := []string{"--force", "plugin-name"}
	norm3 := normalizeArgs(args3)
	if len(norm3) != 2 || norm3[0] != "--force" || norm3[1] != "plugin-name" {
		t.Errorf("unexpected norm3: %v", norm3)
	}
}

func TestTCPWarden_HelperFunctions(t *testing.T) {
	// contains
	list := []string{"redis", "POSTGRES", "mysql"}
	if !contains(list, "postgres") || !contains(list, "REDIS") {
		t.Errorf("contains failed case-insensitive match")
	}
	if contains(list, "sqlite") {
		t.Errorf("contains should return false for nonexistent item")
	}

	// removeFromList
	rem := removeFromList(list, "Postgres")
	if len(rem) != 2 || contains(rem, "postgres") {
		t.Errorf("removeFromList failed: %v", rem)
	}

	// isStandardProtocol
	if !isStandardProtocol("tcp") || !isStandardProtocol("UDP") || !isStandardProtocol("") {
		t.Errorf("isStandardProtocol failed for standard protocol")
	}
	if isStandardProtocol("redis") || isStandardProtocol("ftp") {
		t.Errorf("isStandardProtocol should return false for plugin protocols")
	}
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTCPWarden_MakeAPIRequest(t *testing.T) {
	var capturedAuth string
	var capturedMethod string
	var capturedBody string

	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		capturedAuth = r.Header.Get("Authorization")
		capturedMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
			Header:     make(http.Header),
		}, nil
	})

	bodyReader := strings.NewReader(`{"ip":"192.0.2.1"}`)
	resp, err := makeAPIRequest("POST", "http://127.0.0.1:8080/api/ban", "secret-token-xyz", bodyReader)
	if err != nil {
		t.Fatalf("makeAPIRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if capturedAuth != "Bearer secret-token-xyz" {
		t.Errorf("expected Bearer token, got %q", capturedAuth)
	}
	if capturedMethod != "POST" {
		t.Errorf("expected POST method, got %q", capturedMethod)
	}
	if capturedBody != `{"ip":"192.0.2.1"}` {
		t.Errorf("unexpected captured body: %q", capturedBody)
	}
}

