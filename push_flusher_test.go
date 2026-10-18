package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/routewarden/cli/crypto"
)

func TestSendBatchWithRetry_EmptyBatch(t *testing.T) {
	called := false
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}),
	}

	err := sendBatchWithRetry(context.Background(), client, "http://example.com", "token", "agent1", "host1", nil, nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}
	if called {
		t.Error("expected no HTTP call for empty batch")
	}
}

func TestSendBatchWithRetry_SuccessAndEncryption(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var receivedEncrypted crypto.EncryptedPayload
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer test-sec-token" {
				t.Errorf("unexpected authorization header: %s", req.Header.Get("Authorization"))
			}

			// Verify request body is encrypted
			if err := json.NewDecoder(req.Body).Decode(&receivedEncrypted); err != nil {
				t.Fatalf("failed to decode encrypted payload: %v", err)
			}

			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusAccepted)
			return rec.Result(), nil
		}),
	}

	batch := []string{
		`{"time":"2026-10-18T12:00:00Z","path":"/test"}`,
	}

	err = sendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "test-sec-token", "agent_123", "host_a", pub, batch)
	if err != nil {
		t.Fatalf("sendBatchWithRetry failed: %v", err)
	}

	// Decrypt on server side and verify contents
	plaintext, err := crypto.Decrypt(priv, &receivedEncrypted)
	if err != nil {
		t.Fatalf("failed to decrypt received payload: %v", err)
	}

	var payload pushPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("failed to parse decrypted json: %v", err)
	}
	if payload.AgentID != "agent_123" || payload.Hostname != "host_a" || len(payload.Events) != 1 {
		t.Errorf("unexpected payload: %+v", payload)
	}
}

func TestSendBatchWithRetry_RetryBackoffRecovery(t *testing.T) {
	var attempts int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			count := atomic.AddInt32(&attempts, 1)
			rec := httptest.NewRecorder()
			if count < 2 {
				// First attempt fails with 503
				rec.WriteHeader(http.StatusServiceUnavailable)
			} else {
				// Second attempt succeeds with 200 OK
				rec.WriteHeader(http.StatusOK)
			}
			return rec.Result(), nil
		}),
	}

	batch := []string{"event 1", "event 2"}
	err := sendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err != nil {
		t.Fatalf("sendBatchWithRetry should have recovered on retry: %v", err)
	}

	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestSendBatchWithRetry_ExhaustionError(t *testing.T) {
	var attempts int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&attempts, 1)
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusInternalServerError)
			return rec.Result(), nil
		}),
	}

	batch := []string{"event 1"}
	err := sendBatchWithRetry(context.Background(), client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err == nil {
		t.Error("expected error after retry exhaustion, got nil")
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestSendBatchWithRetry_ContextCancelled(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusServiceUnavailable)
			return rec.Result(), nil
		}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	batch := []string{"event 1"}
	err := sendBatchWithRetry(ctx, client, "http://localhost:7890/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err == nil {
		t.Error("expected context error, got nil")
	}
}

func TestResolveFileList_RepeatableAndCommaSeparated(t *testing.T) {
	flags := []string{"/var/log/nginx/access.log", "/var/log/caddy/access.log,/var/log/traefik/access.log", " /var/log/nginx/access.log "}
	posArgs := []string{"/var/log/custom.log"}

	files := resolveFileList(flags, posArgs)
	expected := []string{
		"/var/log/nginx/access.log",
		"/var/log/caddy/access.log",
		"/var/log/traefik/access.log",
		"/var/log/custom.log",
	}

	if len(files) != len(expected) {
		t.Fatalf("expected %d files, got %d: %v", len(expected), len(files), files)
	}
	for i, f := range files {
		if f != expected[i] {
			t.Errorf("at index %d: expected %s, got %s", i, expected[i], f)
		}
	}
}

func TestResolveFileList_GlobPattern(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "node1_app.log")
	f2 := filepath.Join(tmpDir, "node2_app.log")
	f3 := filepath.Join(tmpDir, "other.txt")

	_ = os.WriteFile(f1, []byte("log 1\n"), 0600)
	_ = os.WriteFile(f2, []byte("log 2\n"), 0600)
	_ = os.WriteFile(f3, []byte("text\n"), 0600)

	globPattern := filepath.Join(tmpDir, "*_app.log")
	files := resolveFileList([]string{globPattern}, nil)

	if len(files) != 2 {
		t.Fatalf("expected 2 files from glob, got %d: %v", len(files), files)
	}
	if files[0] != f1 && files[0] != f2 {
		t.Errorf("unexpected file in results: %s", files[0])
	}
}

func TestResolveContainerList_RepeatableAndCommaSeparated(t *testing.T) {
	flags := []string{"traefik", "caddy,api-gateway", " traefik ", ""}
	containers := resolveContainerList(flags)

	expected := []string{"traefik", "caddy", "api-gateway"}
	if len(containers) != len(expected) {
		t.Fatalf("expected %d containers, got %d: %v", len(expected), len(containers), containers)
	}
	for i, c := range containers {
		if c != expected[i] {
			t.Errorf("at index %d: expected %s, got %s", i, expected[i], c)
		}
	}
}

func TestPushFlagResolution_Matrix(t *testing.T) {
	tests := []struct {
		name               string
		fileFlags          []string
		posArgs            []string
		containerFlags     []string
		dockerMode         bool
		wantFileCount      int
		wantContainerCount int
		wantDockerDiscover bool
	}{
		{
			name:               "zero flags defaults to docker auto-discovery",
			fileFlags:          nil,
			posArgs:            nil,
			containerFlags:     nil,
			dockerMode:         false,
			wantFileCount:      0,
			wantContainerCount: 0,
			wantDockerDiscover: true,
		},
		{
			name:               "single file disables docker auto-discovery",
			fileFlags:          []string{"/var/log/nginx.log"},
			posArgs:            nil,
			containerFlags:     nil,
			dockerMode:         false,
			wantFileCount:      1,
			wantContainerCount: 0,
			wantDockerDiscover: false,
		},
		{
			name:               "concurrent file and docker auto-discovery",
			fileFlags:          []string{"/var/log/nginx.log", "/var/log/auth.log"},
			posArgs:            nil,
			containerFlags:     nil,
			dockerMode:         true,
			wantFileCount:      2,
			wantContainerCount: 0,
			wantDockerDiscover: true,
		},
		{
			name:               "concurrent specific container and file and docker auto-discovery",
			fileFlags:          []string{"/var/log/nginx.log"},
			posArgs:            []string{"/var/log/app.log"},
			containerFlags:     []string{"custom-backend,edge-proxy"},
			dockerMode:         true,
			wantFileCount:      2,
			wantContainerCount: 2,
			wantDockerDiscover: true,
		},
		{
			name:               "specific container without docker flag",
			fileFlags:          nil,
			posArgs:            nil,
			containerFlags:     []string{"custom-backend"},
			dockerMode:         false,
			wantFileCount:      0,
			wantContainerCount: 1,
			wantDockerDiscover: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := resolveFileList(tc.fileFlags, tc.posArgs)
			containers := resolveContainerList(tc.containerFlags)
			runDocker := tc.dockerMode || (len(files) == 0 && len(containers) == 0)

			if len(files) != tc.wantFileCount {
				t.Errorf("files: got %d, want %d", len(files), tc.wantFileCount)
			}
			if len(containers) != tc.wantContainerCount {
				t.Errorf("containers: got %d, want %d", len(containers), tc.wantContainerCount)
			}
			if runDocker != tc.wantDockerDiscover {
				t.Errorf("docker auto-discovery: got %v, want %v", runDocker, tc.wantDockerDiscover)
			}
		})
	}
}

func TestTailFileToChan_StreamsLines(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "rwarden_tail_test_*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString("line 1\nline 2\n")
	_ = tmpFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch := make(chan string, 10)
	go tailFileToChan(ctx, tmpFile.Name(), "10", ch)

	var lines []string
	timer := time.After(1 * time.Second)
loop:
	for {
		select {
		case line := <-ch:
			lines = append(lines, line)
			if len(lines) >= 2 {
				break loop
			}
		case <-timer:
			break loop
		}
	}

	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines tailed, got %d: %v", len(lines), lines)
	}
	if lines[0] != "line 1" || lines[1] != "line 2" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestResolveFileList_EdgeCases(t *testing.T) {
	t.Run("empty and whitespace only", func(t *testing.T) {
		res := resolveFileList([]string{"", "   ", "\t"}, []string{"", "  "})
		if len(res) != 0 {
			t.Errorf("expected 0 files, got %d: %v", len(res), res)
		}
	})

	t.Run("multiple commas and whitespace trimming", func(t *testing.T) {
		res := resolveFileList([]string{",,/var/log/a.log,,,   /var/log/b.log  ,"}, []string{",/var/log/c.log,"})
		expected := []string{"/var/log/a.log", "/var/log/b.log", "/var/log/c.log"}
		if len(res) != len(expected) {
			t.Fatalf("expected %d files, got %d: %v", len(expected), len(res), res)
		}
		for i, v := range expected {
			if res[i] != v {
				t.Errorf("at index %d: expected %s, got %s", i, v, res[i])
			}
		}
	})

	t.Run("glob with zero matches does not keep literal pattern", func(t *testing.T) {
		nonExistentGlob := filepath.Join(t.TempDir(), "nonexistent_*.log")
		res := resolveFileList([]string{nonExistentGlob}, nil)
		if len(res) != 0 {
			t.Errorf("expected 0 files for unmatched glob, got %d: %v", len(res), res)
		}
	})

	t.Run("non-existent direct file path is retained for tail -F retry", func(t *testing.T) {
		directFile := filepath.Join(t.TempDir(), "future.log")
		res := resolveFileList([]string{directFile}, nil)
		if len(res) != 1 || res[0] != directFile {
			t.Errorf("expected direct file retained, got: %v", res)
		}
	})

	t.Run("cross-source deduplication", func(t *testing.T) {
		p := "/var/log/nginx.log"
		res := resolveFileList([]string{p, p + "," + p}, []string{p})
		if len(res) != 1 || res[0] != p {
			t.Errorf("expected exactly 1 deduplicated entry, got %d: %v", len(res), res)
		}
	})
}

func TestResolveContainerList_EdgeCases(t *testing.T) {
	t.Run("empty and comma separators", func(t *testing.T) {
		res := resolveContainerList([]string{"", ",,,", "  ", "app1, ,app2,"})
		expected := []string{"app1", "app2"}
		if len(res) != len(expected) {
			t.Fatalf("expected %d containers, got %d: %v", len(expected), len(res), res)
		}
		for i, v := range expected {
			if res[i] != v {
				t.Errorf("at index %d: expected %s, got %s", i, v, res[i])
			}
		}
	})

	t.Run("deduplication across repeatable flags", func(t *testing.T) {
		res := resolveContainerList([]string{"traefik", "traefik", "gateway", "gateway,traefik"})
		expected := []string{"traefik", "gateway"}
		if len(res) != len(expected) {
			t.Fatalf("expected %d containers, got %d: %v", len(expected), len(res), res)
		}
	})
}

func TestSendBatchWithRetry_ClientErrorNonRetryable(t *testing.T) {
	var callCount int32
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			atomic.AddInt32(&callCount, 1)
			rec := httptest.NewRecorder()
			rec.WriteHeader(http.StatusUnauthorized) // 401
			return rec.Result(), nil
		}),
	}

	batch := []string{"event 1"}
	err := sendBatchWithRetry(context.Background(), client, "http://example.com/api/v1/events", "token", "agent1", "host1", nil, batch)
	if err == nil {
		t.Fatal("expected error for 401 Unauthorized, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 in error string, got: %v", err)
	}
}
