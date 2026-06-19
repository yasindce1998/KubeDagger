package stealth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type Envelope struct {
	Data    string `json:"data"`
	TS      int64  `json:"ts"`
	Version string `json:"v"`
}

type Encoder struct {
	key []byte
}

func NewEncoder(secret string) *Encoder {
	h := sha256.Sum256([]byte(secret))
	return &Encoder{key: h[:]}
}

func (e *Encoder) Encode(plaintext []byte) ([]byte, error) {
	keystream := e.deriveKeystream(len(plaintext))
	ciphertext := xorBytes(plaintext, keystream)

	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	envelope := Envelope{
		Data:    encoded,
		TS:      time.Now().Unix(),
		Version: "2.1.0",
	}

	return json.Marshal(envelope)
}

func (e *Encoder) Decode(data []byte) ([]byte, error) {
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Data)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	keystream := e.deriveKeystream(len(ciphertext))
	return xorBytes(ciphertext, keystream), nil
}

func (e *Encoder) deriveKeystream(length int) []byte {
	stream := make([]byte, 0, length)
	counter := uint32(0)
	for len(stream) < length {
		mac := hmac.New(sha256.New, e.key)
		counterBytes := []byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)}
		mac.Write(counterBytes)
		stream = append(stream, mac.Sum(nil)...)
		counter++
	}
	return stream[:length]
}

func xorBytes(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i]
	}
	return result
}
