package crypto

import "context"

type Cipher interface {
	Encrypt(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext, aad []byte) ([]byte, error)
}

type KeyGenerator interface {
	Generate(size int) ([]byte, error)
}
