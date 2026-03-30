// Package auth provides encryption helpers for secrets at rest.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const encPrefix = "enc::"

// DeriveKey derives a 256-bit AES key from the admin key using SHA-256.
func DeriveKey(adminKey string) []byte {
	h := sha256.Sum256([]byte("simpleauth-encrypt:" + adminKey))
	return h[:]
}

// EncryptSecret encrypts a plaintext secret using AES-256-GCM.
// Returns a string prefixed with "enc::" followed by base64-encoded ciphertext.
func EncryptSecret(plaintext string, key []byte) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSecret decrypts a secret encrypted by EncryptSecret.
// If the input is not prefixed with "enc::", it's returned as-is (plaintext migration).
func DecryptSecret(encoded string, key []byte) (string, error) {
	if encoded == "" {
		return "", nil
	}
	if !strings.HasPrefix(encoded, encPrefix) {
		return encoded, nil // plaintext — not yet encrypted (migration)
	}

	data, err := base64.StdEncoding.DecodeString(encoded[len(encPrefix):])
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}

// IsEncrypted returns true if the string is already encrypted.
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, encPrefix)
}
