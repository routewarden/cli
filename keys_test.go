package main

import (
	"os"
	"strings"
	"testing"

	"github.com/routewarden/cli/observability"
)

func TestKeys_Lifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-keys-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Ensure server keypair creates files
	priv, pub, err := observability.EnsureServerKeypair(tempDir)
	if err != nil {
		t.Fatalf("EnsureServerKeypair failed: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatalf("expected non-nil keypair")
	}

	// 2. Second call should load existing keypair
	priv2, pub2, err := observability.EnsureServerKeypair(tempDir)
	if err != nil {
		t.Fatalf("second EnsureServerKeypair call failed: %v", err)
	}
	if string(priv.Bytes()) != string(priv2.Bytes()) {
		t.Errorf("expected identical keypair on reload")
	}
	_ = pub2

	// 3. Create agent key
	rawToken, agentKey, err := observability.CreateAgentKey("edge-cluster-1", tempDir)
	if err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}
	if !strings.HasPrefix(rawToken, "rw_sec_") {
		t.Errorf("expected token prefix rw_sec_, got: %s", rawToken)
	}
	if agentKey.Name != "edge-cluster-1" {
		t.Errorf("expected name edge-cluster-1, got: %s", agentKey.Name)
	}

	// 4. Duplicate creation should fail
	_, _, err = observability.CreateAgentKey("edge-cluster-1", tempDir)
	if err == nil {
		t.Errorf("expected error on duplicate key name, got nil")
	}

	// 5. List keys
	keys, err := observability.ListAgentKeys(tempDir)
	if err != nil {
		t.Fatalf("ListAgentKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// 6. Validate token
	validated, err := observability.ValidateAgentToken(rawToken, tempDir)
	if err != nil {
		t.Fatalf("ValidateAgentToken failed: %v", err)
	}
	if validated.ID != agentKey.ID {
		t.Errorf("expected ID %s, got %s", agentKey.ID, validated.ID)
	}

	// 7. Update last seen
	observability.UpdateAgentLastSeen(agentKey.ID, tempDir)
	keys, _ = observability.ListAgentKeys(tempDir)
	if keys[0].LastSeenAt == "" {
		t.Errorf("expected non-empty LastSeenAt")
	}

	// 8. Revoke key
	if err := observability.RevokeAgentKey(agentKey.ID, tempDir); err != nil {
		t.Fatalf("RevokeAgentKey failed: %v", err)
	}

	// 9. Validation after revoke should fail
	_, err = observability.ValidateAgentToken(rawToken, tempDir)
	if err == nil {
		t.Errorf("expected error validating revoked token, got nil")
	}
}
