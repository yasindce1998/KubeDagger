package k8sc2

import (
	"encoding/base64"
)

func Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func Decode(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}
