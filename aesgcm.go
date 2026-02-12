package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	NonceSize = 12
)

type AESGCM struct {
	aead cipher.AEAD
}

func NewAESGCM(key []byte) (*AESGCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESGCM{aead: aead}, nil
}

func (a *AESGCM) Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Preallocate: nonce + ciphertext + tag
	ciphertext := a.aead.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, NonceSize+len(ciphertext))
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func (a *AESGCM) Decrypt(ctx context.Context, input, aad []byte) ([]byte, error) {
	if len(input) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := input[:NonceSize]
	ciphertext := input[NonceSize:]

	return a.aead.Open(nil, nonce, ciphertext, aad)
}
