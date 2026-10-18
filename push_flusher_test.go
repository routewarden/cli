package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
