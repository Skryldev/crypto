package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize       = 16
	DefaultIter    = 100_000
	DefaultKeySize = 32
)

func DeriveKey(password []byte, salt []byte, iter int, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	return salt, err
}
