package crypto_test

import (
	"bytes"
	"testing"

	"github.com/routewarden/cli/crypto"
)

func TestCrypto_EncryptDecrypt(t *testing.T) {
	// Generate keypair for receiver
	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte(`{"agent_id":"edge-node-1","events":[{"path":"/.env","verdict":"BLOCK"}]}`)

	// Encrypt using recipient public key
	encrypted, err := crypto.Encrypt(pub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if encrypted.Ciphertext == "" || encrypted.Nonce == "" || encrypted.EphemeralPub == "" {
		t.Fatalf("expected non-empty fields in EncryptedPayload, got %+v", encrypted)
	}

	// Decrypt using recipient private key
	decrypted, err := crypto.Decrypt(priv, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text mismatch.\nExpected: %s\nGot:      %s", plaintext, decrypted)
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
	tamperedPayload.Ciphertext = "dGFtcGVyZWQ=" // base64 "tampered"

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

	// Test encrypt/decrypt with decoded keys
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
