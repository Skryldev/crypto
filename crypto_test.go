package crypto

import (
	"context"
	"testing"
)

func TestAESGCM(t *testing.T) {
	keyGen := DefaultKeyGenerator{}
	key, _ := keyGen.Generate(32)

	c, err := NewAESGCM(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secure message")

	ciphertext, err := c.Encrypt(context.Background(), plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}

	out, err := c.Decrypt(context.Background(), ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != string(plaintext) {
		t.Fatal("decryption mismatch")
	}
}
