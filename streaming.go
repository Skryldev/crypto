package crypto

import (
	"context"
	"io"
)

const ChunkSize = 32 * 1024

func EncryptStream(c Cipher, r io.Reader, w io.Writer) error {
	buf := make([]byte, ChunkSize)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			enc, err2 := c.Encrypt(context.Background(), buf[:n], nil)
			if err2 != nil {
				return err2
			}
			if _, err2 = w.Write(enc); err2 != nil {
				return err2
			}
		}

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// DecryptStream decrypts a large file or stream in chunks
func DecryptStream(c Cipher, r io.Reader, w io.Writer) error {
	buf := make([]byte, ChunkSize+NonceSize+16) // 16 = GCM tag
	chunk := make([]byte, 0, ChunkSize+NonceSize+16)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk = buf[:n]

			plaintext, err := c.Decrypt(context.Background(), chunk, nil)
			if err != nil {
				return err
			}

			if _, err := w.Write(plaintext); err != nil {
				return err
			}
		}

		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}
	}
}

