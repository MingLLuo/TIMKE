package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

var (
	ErrInvalidKey        = errors.New("invalid key")
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

type SymmetricEncryption interface {
	Encrypt(key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

type AESGCM struct {
	nonceSize int
	random    io.Reader
}

func NewAESGCM() *AESGCM {
	return &AESGCM{
		nonceSize: 12,
		random:    rand.Reader,
	}
}

func (a *AESGCM) normalizeKey(key []byte) []byte {
	if len(key) == 16 || len(key) == 24 || len(key) == 32 {
		return key
	}

	h := sha256.New()
	h.Write(key)
	normKey := h.Sum(nil)

	return normKey
}

func (a *AESGCM) Encrypt(key, plaintext []byte) ([]byte, error) {
	normalizedKey := a.normalizeKey(key)

	block, err := aes.NewCipher(normalizedKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, a.nonceSize)
	if _, err := io.ReadFull(a.random, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, a.nonceSize+len(ciphertext))
	copy(result[:a.nonceSize], nonce)
	copy(result[a.nonceSize:], ciphertext)

	return result, nil
}

func (a *AESGCM) Decrypt(key, ciphertext []byte) ([]byte, error) {
	normalizedKey := a.normalizeKey(key)

	if len(ciphertext) < a.nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce := ciphertext[:a.nonceSize]
	ciphertext = ciphertext[a.nonceSize:]

	block, err := aes.NewCipher(normalizedKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func DefaultSymmetricEncryption() SymmetricEncryption {
	return NewAESGCM()
}
