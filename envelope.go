package crypto

import "errors"

const (
	Version1 byte = 0x01
)

type Envelope struct {
	Version byte
	Data    []byte
}

func Wrap(version byte, payload []byte) []byte {
	out := make([]byte, 0, 1+len(payload))
	out = append(out, version)
	out = append(out, payload...)
	return out
}

func Unwrap(input []byte) (*Envelope, error) {
	if len(input) < 1 {
		return nil, errors.New("invalid envelope")
	}

	return &Envelope{
		Version: input[0],
		Data:    input[1:],
	}, nil
}
