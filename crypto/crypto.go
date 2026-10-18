package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const hkdfInfo = "routewarden-v1-log-encryption"

// EncryptedPayload contains the ciphertext and ephemeral key for X25519+AES-GCM encryption.
type EncryptedPayload struct {
	EphemeralPub string `json:"ephemeral_pub"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// GenerateKeyPair generates a new X25519 keypair.
func GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// EncodePrivateKey returns the Base64 representation of an X25519 private key.
func EncodePrivateKey(key *ecdh.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

// DecodePrivateKey parses an X25519 private key from Base64.
func DecodePrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64 private key: %w", err)
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// EncodePublicKey returns the Base64 representation of an X25519 public key.
func EncodePublicKey(key *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key.Bytes())
}

// DecodePublicKey parses an X25519 public key from Base64.
func DecodePublicKey(encoded string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode base64 public key: %w", err)
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// Encrypt encrypts plaintext using the recipient's X25519 public key via hybrid ECDH + AES-256-GCM.
func Encrypt(recipientPub *ecdh.PublicKey, plaintext []byte) (*EncryptedPayload, error) {
	if recipientPub == nil {
		return nil, errors.New("recipient public key cannot be nil")
	}

	// 1. Generate ephemeral keypair
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// 2. Compute shared secret
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("compute ECDH shared secret: %w", err)
	}

	// 3. Derive symmetric key using simple HKDF
	aesKey := deriveSymmetricKey(sharedSecret)

	// 4. AES-GCM Encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedPayload{
		EphemeralPub: EncodePublicKey(ephemeralPriv.PublicKey()),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// Decrypt decrypts an EncryptedPayload using the recipient's X25519 private key.
func Decrypt(recipientPriv *ecdh.PrivateKey, payload *EncryptedPayload) ([]byte, error) {
	if recipientPriv == nil {
		return nil, errors.New("recipient private key cannot be nil")
	}
	if payload == nil {
		return nil, errors.New("payload cannot be nil")
	}

	// 1. Decode Ephemeral Public Key
	ephemeralPub, err := DecodePublicKey(payload.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// 2. Compute shared secret
	sharedSecret, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("compute ECDH shared secret: %w", err)
	}

	// 3. Derive symmetric key
	aesKey := deriveSymmetricKey(sharedSecret)

	// 4. AES-GCM Decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

// deriveSymmetricKey derives a 32-byte AES key from a shared secret using SHA-256.
func deriveSymmetricKey(sharedSecret []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte(hkdfInfo))
	return h.Sum(nil)
}
