package observability

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/routewarden/cli/crypto"
)

var keyStoreMu sync.RWMutex

// AgentKey represents a registered remote agent key in the store.
type AgentKey struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	TokenHash  string `json:"token_hash"`
	Prefix     string `json:"prefix"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	Revoked    bool   `json:"revoked"`
}

// KeyStore persists agent credentials.
type KeyStore struct {
	Keys []AgentKey `json:"keys"`
}

func defaultKeyStorePath(customDir string) string {
	if customDir == "" {
		customDir = DefaultDir()
	}
	return filepath.Join(customDir, "api_keys.json")
}

// EnsureServerKeypair loads or generates the master server X25519 keypair.
func EnsureServerKeypair(dir string) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create keys directory: %w", err)
	}

	privPath := filepath.Join(dir, "server.key")
	pubPath := filepath.Join(dir, "server.pub")

	// Try reading existing keypair
	if privData, err := os.ReadFile(privPath); err == nil {
		priv, err := crypto.DecodePrivateKey(strings.TrimSpace(string(privData)))
		if err == nil {
			return priv, priv.PublicKey(), nil
		}
	}

	// Generate new keypair
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	privStr := crypto.EncodePrivateKey(priv)
	pubStr := crypto.EncodePublicKey(pub)

	if err := os.WriteFile(privPath, []byte(privStr), 0600); err != nil {
		return nil, nil, fmt.Errorf("save private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubStr), 0644); err != nil {
		return nil, nil, fmt.Errorf("save public key: %w", err)
	}

	return priv, pub, nil
}

// GetServerPublicKey returns the encoded public key of the server.
func GetServerPublicKey(dir string) (string, error) {
	_, pub, err := EnsureServerKeypair(dir)
	if err != nil {
		return "", err
	}
	return crypto.EncodePublicKey(pub), nil
}

func loadKeyStore(path string) (*KeyStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &KeyStore{Keys: []AgentKey{}}, nil
		}
		return nil, err
	}

	var store KeyStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return &store, nil
}

func saveKeyStore(path string, store *KeyStore) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// CreateAgentKey creates a new remote agent token and persists its hash.
func CreateAgentKey(name, dir string) (string, *AgentKey, error) {
	keyStoreMu.Lock()
	defer keyStoreMu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, fmt.Errorf("agent name cannot be empty")
	}

	storePath := defaultKeyStorePath(dir)
	store, err := loadKeyStore(storePath)
	if err != nil {
		return "", nil, fmt.Errorf("load keystore: %w", err)
	}

	// Check duplicates
	for _, k := range store.Keys {
		if k.Name == name && !k.Revoked {
			return "", nil, fmt.Errorf("an active key with name %q already exists (revoke it first)", name)
		}
	}

	// Generate random 16-byte ID and 24-byte secret token
	idBytes := make([]byte, 8)
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, err
	}
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, err
	}

	id := "agent_" + hex.EncodeToString(idBytes)
	rawToken := "rw_sec_" + hex.EncodeToString(tokenBytes)
	prefix := rawToken[:13] + "..."

	agentKey := AgentKey{
		ID:        id,
		Name:      name,
		TokenHash: hashToken(rawToken),
		Prefix:    prefix,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Revoked:   false,
	}

	store.Keys = append(store.Keys, agentKey)
	if err := saveKeyStore(storePath, store); err != nil {
		return "", nil, fmt.Errorf("save keystore: %w", err)
	}

	return rawToken, &agentKey, nil
}

// ListAgentKeys returns all registered keys.
func ListAgentKeys(dir string) ([]AgentKey, error) {
	keyStoreMu.RLock()
	defer keyStoreMu.RUnlock()

	store, err := loadKeyStore(defaultKeyStorePath(dir))
	if err != nil {
		return nil, err
	}
	return store.Keys, nil
}

// RevokeAgentKey marks a key as revoked.
func RevokeAgentKey(idOrName, dir string) error {
	keyStoreMu.Lock()
	defer keyStoreMu.Unlock()

	storePath := defaultKeyStorePath(dir)
	store, err := loadKeyStore(storePath)
	if err != nil {
		return err
	}

	found := false
	for i := range store.Keys {
		if store.Keys[i].ID == idOrName || store.Keys[i].Name == idOrName {
			store.Keys[i].Revoked = true
			found = true
		}
	}

	if !found {
		return fmt.Errorf("key %q not found", idOrName)
	}

	return saveKeyStore(storePath, store)
}

// ValidateAgentToken verifies an incoming raw token against the keystore.
func ValidateAgentToken(rawToken, dir string) (*AgentKey, error) {
	keyStoreMu.RLock()
	defer keyStoreMu.RUnlock()

	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("empty token")
	}

	tokenHash := hashToken(rawToken)
	store, err := loadKeyStore(defaultKeyStorePath(dir))
	if err != nil {
		return nil, err
	}

	for _, k := range store.Keys {
		if subtle.ConstantTimeCompare([]byte(k.TokenHash), []byte(tokenHash)) == 1 {
			if k.Revoked {
				return nil, fmt.Errorf("key has been revoked")
			}
			return &k, nil
		}
	}

	return nil, fmt.Errorf("invalid API key")
}

// UpdateAgentLastSeen updates the last seen timestamp for an agent.
func UpdateAgentLastSeen(agentID, dir string) {
	keyStoreMu.Lock()
	defer keyStoreMu.Unlock()

	storePath := defaultKeyStorePath(dir)
	store, err := loadKeyStore(storePath)
	if err != nil {
		return
	}

	for i := range store.Keys {
		if store.Keys[i].ID == agentID {
			store.Keys[i].LastSeenAt = time.Now().UTC().Format(time.RFC3339)
			_ = saveKeyStore(storePath, store)
			return
		}
	}
}
