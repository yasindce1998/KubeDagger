package c2

import (
	"encoding/hex"
	"net"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestDeriveKeyFromHex(t *testing.T) {
	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key, err := DeriveKey(hexKey)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		t.Errorf("key length = %d, want %d", len(key), chacha20poly1305.KeySize)
	}

	expected, _ := hex.DecodeString(hexKey)
	for i := range key {
		if key[i] != expected[i] {
			t.Fatalf("key mismatch at byte %d", i)
		}
	}
}

func TestDeriveKeyFromPassphrase(t *testing.T) {
	key, err := DeriveKey("short")
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		t.Errorf("key length = %d, want %d", len(key), chacha20poly1305.KeySize)
	}
	if string(key[:5]) != "short" {
		t.Error("passphrase not copied into key")
	}
	for i := 5; i < len(key); i++ {
		if key[i] != 0 {
			t.Errorf("expected zero padding at byte %d, got %d", i, key[i])
		}
	}
}

func TestDeriveKeyInvalidHex(t *testing.T) {
	key, err := DeriveKey("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	if err != nil {
		t.Fatalf("DeriveKey should not error on invalid hex: %v", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		t.Errorf("key length = %d, want %d", len(key), chacha20poly1305.KeySize)
	}
}

func TestGenerateKey(t *testing.T) {
	hexStr, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(hexStr) != 64 {
		t.Errorf("hex key length = %d, want 64", len(hexStr))
	}

	key, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("generated key is not valid hex: %v", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		t.Errorf("decoded key length = %d, want %d", len(key), chacha20poly1305.KeySize)
	}
}

func TestGenerateKeyUniqueness(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	if key1 == key2 {
		t.Error("two generated keys should not be identical")
	}
}

func TestWriteReadEncryptedRoundTrip(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	plaintext := []byte("hello encrypted c2 world")
	errCh := make(chan error, 1)

	go func() {
		errCh <- writeEncrypted(client, key, plaintext)
	}()

	got, err := readEncrypted(server, key)
	if err != nil {
		t.Fatalf("readEncrypted failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("writeEncrypted failed: %v", err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestWriteReadEncryptedEmpty(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i + 42)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go writeEncrypted(client, key, []byte{})

	got, err := readEncrypted(server, key)
	if err != nil {
		t.Fatalf("readEncrypted failed on empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestWriteReadEncryptedWrongKey(t *testing.T) {
	key1 := make([]byte, chacha20poly1305.KeySize)
	key2 := make([]byte, chacha20poly1305.KeySize)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go writeEncrypted(client, key1, []byte("secret"))

	_, err := readEncrypted(server, key2)
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}

func TestWriteReadEncryptedLargeMessage(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	plaintext := make([]byte, 32768)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	go writeEncrypted(client, key, plaintext)

	got, err := readEncrypted(server, key)
	if err != nil {
		t.Fatalf("readEncrypted failed: %v", err)
	}
	if len(got) != len(plaintext) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(plaintext))
	}
	for i := range got {
		if got[i] != plaintext[i] {
			t.Fatalf("mismatch at byte %d", i)
		}
	}
}

func TestNewServerInvalidKey(t *testing.T) {
	_, err := NewServer([]byte("short"), func(cmd []byte) ([]byte, error) { return nil, nil })
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestNewClientInvalidKey(t *testing.T) {
	_, err := NewClient([]byte("short"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestNewServerValidKey(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	s, err := NewServer(key, func(cmd []byte) ([]byte, error) { return cmd, nil })
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if s == nil {
		t.Fatal("server is nil")
	}
}

func TestNewClientValidKey(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	c, err := NewClient(key)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

func TestServerClientIntegration(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	handler := func(cmd []byte) ([]byte, error) {
		return append([]byte("echo:"), cmd...), nil
	}

	srv, err := NewServer(key, handler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	client, err := NewClient(key)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.Connect(addr); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	resp, err := client.SendCommand([]byte("ping"))
	if err != nil {
		t.Fatalf("SendCommand: %v", err)
	}

	if string(resp) != "echo:ping" {
		t.Errorf("got %q, want %q", resp, "echo:ping")
	}
}
