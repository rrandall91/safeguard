package safeguard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

var (
	// ErrEncryptionKeyEmpty is returned when the EncryptionKey is empty.
	ErrEncryptionKeyEmpty = Error("encryption key is empty")
)

type Safeguard struct {
	*Config
}

// Returns a new Safeguard.
func New(c *Config) *Safeguard {
	return &Safeguard{
		Config: c,
	}
}

// Hash returns a SHA256 hash of the given plaintext.
func (s *Safeguard) Hash(plaintext string) (hash string, err error) {
	h := sha256.New()

	_, err = h.Write([]byte(plaintext))
	if err != nil {
		return
	}

	hash = fmt.Sprintf("%x", h.Sum(nil))

	return
}

// Encrypt returns a base64 encoded AES-GCM ciphertext.
func (s *Safeguard) Encrypt(plaintext string) (ciphertext string, err error) {
	if s.Config.EncryptionKey == "" {
		err = ErrEncryptionKeyEmpty
		return
	}

	block, err := aes.NewCipher([]byte(s.Config.EncryptionKey))
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	ciphertextbyte := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	ciphertext = base64.StdEncoding.EncodeToString(ciphertextbyte)

	return
}

// Decrypt returns the plaintext of the given base64 encoded AES-GCM ciphertext.
func (s *Safeguard) Decrypt(ciphertext string) (plaintext string, err error) {
	if s.Config.EncryptionKey == "" {
		err = ErrEncryptionKeyEmpty
		return
	}

	ciphertextbyte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return
	}

	block, err := aes.NewCipher([]byte(s.Config.EncryptionKey))
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	nonce := ciphertextbyte[:gcm.NonceSize()]
	plaintextbyte, err := gcm.Open(nil, nonce, ciphertextbyte[gcm.NonceSize():], nil)
	if err != nil {
		return
	}

	plaintext = string(plaintextbyte)

	return
}
