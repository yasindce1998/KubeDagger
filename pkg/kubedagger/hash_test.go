package kubedagger

import (
	"testing"
)

func TestFNVHashStr(t *testing.T) {
	h1 := FNVHashStr("hello")
	h2 := FNVHashStr("hello")
	h3 := FNVHashStr("world")

	if h1 != h2 {
		t.Errorf("same input produced different hashes: %d vs %d", h1, h2)
	}
	if h1 == h3 {
		t.Errorf("different inputs produced same hash: %d", h1)
	}
	if h1 == 0 {
		t.Error("hash should not be zero")
	}
}

func TestFNVHashByte(t *testing.T) {
	h1 := FNVHashByte([]byte{1, 2, 3})
	h2 := FNVHashByte([]byte{1, 2, 3})
	h3 := FNVHashByte([]byte{4, 5, 6})

	if h1 != h2 {
		t.Error("same input produced different hashes")
	}
	if h1 == h3 {
		t.Error("different inputs produced same hash")
	}
}

func TestFNVHashInt(t *testing.T) {
	h1 := FNVHashInt(42)
	h2 := FNVHashInt(42)
	h3 := FNVHashInt(99)

	if h1 != h2 {
		t.Error("same input produced different hashes")
	}
	if h1 == h3 {
		t.Error("different inputs produced same hash")
	}
}
