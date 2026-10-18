package observability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeystore_ServerKeypair_PermissionsAndReload(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-keys-perm-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Initial generation
	priv, pub, err := EnsureServerKeypair(tempDir)
	if err != nil {
		t.Fatalf("EnsureServerKeypair failed: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("expected non-nil server keypair")
	}

	privPath := filepath.Join(tempDir, "server.key")
	pubPath := filepath.Join(tempDir, "server.pub")

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat server.key: %v", err)
	}
	// Private key must be 0600
	if privInfo.Mode().Perm() != 0600 {
		t.Errorf("expected server.key permissions 0600, got %o", privInfo.Mode().Perm())
	}

	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat server.pub: %v", err)
	}
	if pubInfo.Mode().Perm() != 0644 {
		t.Errorf("expected server.pub permissions 0644, got %o", pubInfo.Mode().Perm())
	}

	// 2. Public key getter
	pubStr, err := GetServerPublicKey(tempDir)
	if err != nil {
		t.Fatalf("GetServerPublicKey failed: %v", err)
	}
	if pubStr == "" {
		t.Error("expected non-empty public key string")
	}

	// 3. Reloading existing keypair should match
	priv2, pub2, err := EnsureServerKeypair(tempDir)
	if err != nil {
		t.Fatalf("EnsureServerKeypair reload failed: %v", err)
	}
	if string(priv.Bytes()) != string(priv2.Bytes()) {
		t.Error("reloaded private key does not match original")
	}
	if string(pub.Bytes()) != string(pub2.Bytes()) {
		t.Error("reloaded public key does not match original")
	}
}

func TestKeystore_AgentKey_ValidationAndNaming(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-keys-val-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Empty name rejection
	_, _, err = CreateAgentKey("", tempDir)
	if err == nil {
		t.Error("expected error creating agent key with empty name, got nil")
	}

	// Whitespace-only name rejection
	_, _, err = CreateAgentKey("   \t  \n ", tempDir)
	if err == nil {
		t.Error("expected error creating agent key with whitespace name, got nil")
	}

	// Valid creation
	token, key, err := CreateAgentKey("  prod-gateway-1  ", tempDir)
	if err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}
	if key.Name != "prod-gateway-1" {
		t.Errorf("expected trimmed name 'prod-gateway-1', got %q", key.Name)
	}
	if !strings.HasPrefix(token, "rw_sec_") {
		t.Errorf("expected token to start with 'rw_sec_', got %s", token)
	}
	if !strings.HasPrefix(key.Prefix, "rw_sec_") || !strings.HasSuffix(key.Prefix, "...") {
		t.Errorf("unexpected token prefix preview: %s", key.Prefix)
	}
	if key.Revoked {
		t.Error("newly created key must not be revoked")
	}
	if key.LastSeenAt != "" {
		t.Errorf("expected empty LastSeenAt on creation, got %s", key.LastSeenAt)
	}

	// Duplicate name rejection while active
	_, _, err = CreateAgentKey("prod-gateway-1", tempDir)
	if err == nil {
		t.Error("expected error on duplicate active key name, got nil")
	}

	// Revoke by name
	if err := RevokeAgentKey("prod-gateway-1", tempDir); err != nil {
		t.Fatalf("RevokeAgentKey failed: %v", err)
	}

	// Recreate key with same name after revocation must now succeed
	token2, key2, err := CreateAgentKey("prod-gateway-1", tempDir)
	if err != nil {
		t.Fatalf("CreateAgentKey after revocation should succeed: %v", err)
	}
	if token2 == token {
		t.Error("newly created token should be unique from revoked token")
	}
	if key2.ID == key.ID {
		t.Error("newly created key ID should be unique")
	}

	// List keys should show 2 keys (1 revoked, 1 active)
	keys, err := ListAgentKeys(tempDir)
	if err != nil {
		t.Fatalf("ListAgentKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys in store, got %d", len(keys))
	}
}

func TestKeystore_ValidationAndRevocation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-keys-tok-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	token, key, err := CreateAgentKey("cluster-node-a", tempDir)
	if err != nil {
		t.Fatal(err)
	}

	// Valid token authentication
	validated, err := ValidateAgentToken(token, tempDir)
	if err != nil {
		t.Fatalf("ValidateAgentToken failed: %v", err)
	}
	if validated.ID != key.ID || validated.Name != key.Name {
		t.Errorf("mismatched validated key: %+v vs %+v", validated, key)
	}

	// Invalid / empty tokens
	if _, err := ValidateAgentToken("", tempDir); err == nil {
		t.Error("expected error on empty token")
	}
	if _, err := ValidateAgentToken("   ", tempDir); err == nil {
		t.Error("expected error on whitespace token")
	}
	if _, err := ValidateAgentToken("rw_sec_wrong_token_1234567890", tempDir); err == nil {
		t.Error("expected error on nonexistent token")
	}

	// Revoke by ID
	if err := RevokeAgentKey(key.ID, tempDir); err != nil {
		t.Fatalf("RevokeAgentKey by ID failed: %v", err)
	}

	// Token should now be rejected as revoked
	_, err = ValidateAgentToken(token, tempDir)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected 'revoked' error, got %v", err)
	}

	// Revoke nonexistent key
	if err := RevokeAgentKey("agent_non_existent", tempDir); err == nil {
		t.Error("expected error revoking nonexistent key")
	}
}

func TestKeystore_UpdateLastSeen(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-keys-seen-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	_, key, err := CreateAgentKey("monitor-test", tempDir)
	if err != nil {
		t.Fatal(err)
	}

	// Update last seen
	UpdateAgentLastSeen(key.ID, tempDir)

	keys, err := ListAgentKeys(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].LastSeenAt == "" {
		t.Error("expected non-empty LastSeenAt")
	}

	// Updating nonexistent ID should be a no-op (no panic or crash)
	UpdateAgentLastSeen("agent_unknown", tempDir)
}

func TestKeystore_CorruptedStoreFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rw-keys-corrupt-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	storePath := filepath.Join(tempDir, "api_keys.json")
	if err := os.WriteFile(storePath, []byte(`{invalid-json`), 0600); err != nil {
		t.Fatal(err)
	}

	// Load / list should fail gracefully with unmarshal error
	_, err = ListAgentKeys(tempDir)
	if err == nil {
		t.Error("expected error loading corrupted keystore, got nil")
	}

	// Create should fail gracefully
	_, _, err = CreateAgentKey("test", tempDir)
	if err == nil {
		t.Error("expected error creating key in corrupted keystore, got nil")
	}

	// Validate should fail gracefully
	_, err = ValidateAgentToken("rw_sec_test", tempDir)
	if err == nil {
		t.Error("expected error validating token in corrupted keystore, got nil")
	}
}
