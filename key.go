package crypto

import (
	"crypto/rand"
)

type DefaultKeyGenerator struct{}

func (DefaultKeyGenerator) Generate(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	return key, err
}
