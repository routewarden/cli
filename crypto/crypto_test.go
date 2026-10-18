package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/routewarden/cli/crypto"
)

func TestCrypto_EncryptDecrypt(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte(`{"agent_id":"edge-node-1","events":[{"path":"/.env","verdict":"BLOCK"}]}`)

	encrypted, err := crypto.Encrypt(pub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted.Ciphertext == "" || encrypted.Nonce == "" || encrypted.EphemeralPub == "" {
		t.Fatalf("expected non-empty fields in EncryptedPayload, got %+v", encrypted)
	}

	decrypted, err := crypto.Decrypt(priv, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch.\nExpected: %s\nGot:      %s", plaintext, decrypted)
	}
}

func TestCrypto_GenerateKeyPair_Uniqueness(t *testing.T) {
	priv1, pub1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(priv1.Bytes(), priv2.Bytes()) {
		t.Errorf("expected randomly generated private keys to be unique")
	}
	if bytes.Equal(pub1.Bytes(), pub2.Bytes()) {
		t.Errorf("expected randomly generated public keys to be unique")
	}
	if len(pub1.Bytes()) != 32 {
		t.Errorf("expected 32-byte X25519 public key, got %d", len(pub1.Bytes()))
	}
}

func TestCrypto_Decode_InvalidBase64(t *testing.T) {
	_, err := crypto.DecodePrivateKey("not-valid-base64!@#$")
	if err == nil {
		t.Errorf("expected error decoding invalid base64 private key")
	}

	_, err = crypto.DecodePublicKey("not-valid-base64!@#$")
	if err == nil {
		t.Errorf("expected error decoding invalid base64 public key")
	}
}

func TestCrypto_Decode_InvalidKeyLength(t *testing.T) {
	// 16 bytes instead of 32 bytes
	shortKey := base64.StdEncoding.EncodeToString([]byte("too-short-key123"))
	_, err := crypto.DecodePrivateKey(shortKey)
	if err == nil {
		t.Errorf("expected error decoding short private key")
	}

	_, err = crypto.DecodePublicKey(shortKey)
	if err == nil {
		t.Errorf("expected error decoding short public key")
	}
}

func TestCrypto_Encrypt_NilKey(t *testing.T) {
	_, err := crypto.Encrypt(nil, []byte("hello"))
	if err == nil {
		t.Errorf("expected error when encrypting with nil public key")
	}
}

func TestCrypto_Decrypt_NilKeyOrPayload(t *testing.T) {
	priv, _, _ := crypto.GenerateKeyPair()

	_, err := crypto.Decrypt(nil, &crypto.EncryptedPayload{})
	if err == nil {
		t.Errorf("expected error when decrypting with nil private key")
	}

	_, err = crypto.Decrypt(priv, nil)
	if err == nil {
		t.Errorf("expected error when decrypting nil payload")
	}
}

func TestCrypto_Decrypt_CorruptedEphemeralPub(t *testing.T) {
	priv, pub, _ := crypto.GenerateKeyPair()
	encrypted, _ := crypto.Encrypt(pub, []byte("hello"))

	// Corrupt ephemeral public key
	tampered := *encrypted
	tampered.EphemeralPub = base64.StdEncoding.EncodeToString([]byte("invalid-length"))
	_, err := crypto.Decrypt(priv, &tampered)
	if err == nil {
		t.Errorf("expected error decrypting with invalid ephemeral pub key")
	}
}

func TestCrypto_Decrypt_CorruptedNonce(t *testing.T) {
	priv, pub, _ := crypto.GenerateKeyPair()
	encrypted, _ := crypto.Encrypt(pub, []byte("hello"))

	// Nonce altered
	tampered := *encrypted
	tampered.Nonce = "not-valid-base64!!!"
	_, err := crypto.Decrypt(priv, &tampered)
	if err == nil {
		t.Errorf("expected error decrypting with invalid base64 nonce")
	}
}

func TestCrypto_Decrypt_WrongPrivateKey(t *testing.T) {
	_, pub1, _ := crypto.GenerateKeyPair()
	priv2, _, _ := crypto.GenerateKeyPair()

	encrypted, err := crypto.Encrypt(pub1, []byte("confidential"))
	if err != nil {
		t.Fatal(err)
	}

	// Try decrypting with priv2
	_, err = crypto.Decrypt(priv2, encrypted)
	if err == nil {
		t.Errorf("expected decryption error when using wrong private key, got nil")
	}
}

func TestCrypto_LargePayload(t *testing.T) {
	priv, pub, _ := crypto.GenerateKeyPair()

	// 256KB payload
	largeData := strings.Repeat(`{"time":"2026-10-18T11:00:00Z","path":"/api/v1/resource","verdict":"ALLOW"}`+"\n", 3000)

	encrypted, err := crypto.Encrypt(pub, []byte(largeData))
	if err != nil {
		t.Fatalf("failed to encrypt large payload: %v", err)
	}

	decrypted, err := crypto.Decrypt(priv, encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt large payload: %v", err)
	}

	if string(decrypted) != largeData {
		t.Errorf("large payload content mismatch")
	}
}

func TestCrypto_TamperDetection(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := crypto.Encrypt(pub, []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext
	tamperedPayload := *encrypted
	tamperedPayload.Ciphertext = "dGFtcGVyZWQ="

	_, err = crypto.Decrypt(priv, &tamperedPayload)
	if err == nil {
		t.Errorf("expected decryption error on tampered ciphertext, got nil")
	}
}

func TestCrypto_KeyEncoding(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	privStr := crypto.EncodePrivateKey(priv)
	pubStr := crypto.EncodePublicKey(pub)

	decodedPriv, err := crypto.DecodePrivateKey(privStr)
	if err != nil {
		t.Fatalf("DecodePrivateKey failed: %v", err)
	}

	decodedPub, err := crypto.DecodePublicKey(pubStr)
	if err != nil {
		t.Fatalf("DecodePublicKey failed: %v", err)
	}

	encrypted, err := crypto.Encrypt(decodedPub, []byte("roundtrip test"))
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := crypto.Decrypt(decodedPriv, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != "roundtrip test" {
		t.Errorf("expected 'roundtrip test', got '%s'", string(decrypted))
	}
}

func BenchmarkCrypto_EncryptDecrypt(b *testing.B) {
	priv, pub, _ := crypto.GenerateKeyPair()
	payload := []byte(`{"time":"2026-10-18T11:00:00Z","path":"/login","verdict":"BLOCK","rule":"sqli"}`)

	
	for b.Loop() {
		enc, err := crypto.Encrypt(pub, payload)
		if err != nil {
			b.Fatal(err)
		}
		_, err = crypto.Decrypt(priv, enc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Suppress unused import
var _ = rand.Reader
