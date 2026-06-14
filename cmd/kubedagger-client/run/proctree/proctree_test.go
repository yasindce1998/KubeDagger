package proctree

import (
	"encoding/binary"
	"testing"
)

func makeEntry(pid, ppid uint32, startTime uint64, comm string) []byte {
	entry := make([]byte, 32)
	binary.LittleEndian.PutUint32(entry[0:4], pid)
	binary.LittleEndian.PutUint32(entry[4:8], ppid)
	binary.LittleEndian.PutUint64(entry[8:16], startTime)
	copy(entry[16:32], comm)
	return entry
}

func TestParseProcessEntries(t *testing.T) {
	data := append(makeEntry(1, 0, 1000, "init"), makeEntry(42, 1, 2000, "bash")...)
	entries := parseProcessEntries(data)

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].PID != 1 || entries[0].PPID != 0 || entries[0].Comm != "init" {
		t.Errorf("entry 0 mismatch: %+v", entries[0])
	}
	if entries[1].PID != 42 || entries[1].PPID != 1 || entries[1].Comm != "bash" {
		t.Errorf("entry 1 mismatch: %+v", entries[1])
	}
	if entries[0].StartTime != 1000 {
		t.Errorf("entry 0 start time: got %d, want 1000", entries[0].StartTime)
	}
}

func TestParseProcessEntriesEmpty(t *testing.T) {
	entries := parseProcessEntries([]byte{})
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseProcessEntriesStopsOnZero(t *testing.T) {
	data := append(makeEntry(1, 0, 100, "init"), makeEntry(0, 0, 0, "")...)
	data = append(data, makeEntry(99, 1, 500, "ghost")...)

	entries := parseProcessEntries(data)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (stop on zero), got %d", len(entries))
	}
	if entries[0].PID != 1 {
		t.Errorf("expected PID 1, got %d", entries[0].PID)
	}
}

func TestParseProcessEntriesPartialData(t *testing.T) {
	data := makeEntry(1, 0, 100, "init")
	data = append(data, []byte("short")...)

	entries := parseProcessEntries(data)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry with partial trailing data, got %d", len(entries))
	}
}

func TestParseProcessEntriesNullTermComm(t *testing.T) {
	data := makeEntry(5, 1, 300, "cat\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	entries := parseProcessEntries(data)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Comm != "cat" {
		t.Errorf("comm should be trimmed: got %q", entries[0].Comm)
	}
}

func TestBuildUserAgent(t *testing.T) {
	ua := buildUserAgent("0012")
	if len(ua) != 500 {
		t.Errorf("user agent length = %d, want 500", len(ua))
	}
	if ua[:4] != "0012" {
		t.Errorf("user agent prefix = %q, want %q", ua[:4], "0012")
	}
}

func TestBuildUserAgentPadding(t *testing.T) {
	ua := buildUserAgent("x")
	if len(ua) != 500 {
		t.Errorf("user agent length = %d, want 500", len(ua))
	}
	for i := 1; i < 500; i++ {
		if ua[i] != '_' {
			t.Errorf("expected padding char '_' at position %d, got %q", i, ua[i])
			break
		}
	}
}

func TestFindRoots(t *testing.T) {
	entries := []ProcessEntry{
		{PID: 1, PPID: 0, Comm: "init"},
		{PID: 2, PPID: 1, Comm: "bash"},
		{PID: 3, PPID: 1, Comm: "sshd"},
		{PID: 4, PPID: 2, Comm: "vim"},
	}

	children := make(map[uint32][]ProcessEntry)
	for _, e := range entries {
		children[e.PPID] = append(children[e.PPID], e)
	}

	roots := findRoots(entries, children)
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
	if roots[0].PID != 1 {
		t.Errorf("root PID = %d, want 1", roots[0].PID)
	}
}

func TestFindRootsMultiple(t *testing.T) {
	entries := []ProcessEntry{
		{PID: 1, PPID: 100, Comm: "orphan1"},
		{PID: 2, PPID: 200, Comm: "orphan2"},
		{PID: 3, PPID: 1, Comm: "child"},
	}

	children := make(map[uint32][]ProcessEntry)
	for _, e := range entries {
		children[e.PPID] = append(children[e.PPID], e)
	}

	roots := findRoots(entries, children)
	if len(roots) != 2 {
		t.Fatalf("expected 2 roots, got %d", len(roots))
	}
}

func TestFindRootsEmpty(t *testing.T) {
	roots := findRoots(nil, nil)
	if len(roots) != 0 {
		t.Errorf("expected 0 roots for nil input, got %d", len(roots))
	}
}

func TestFindRootsFallback(t *testing.T) {
	entries := []ProcessEntry{
		{PID: 1, PPID: 2, Comm: "a"},
		{PID: 2, PPID: 1, Comm: "b"},
	}

	children := make(map[uint32][]ProcessEntry)
	for _, e := range entries {
		children[e.PPID] = append(children[e.PPID], e)
	}

	roots := findRoots(entries, children)
	if len(roots) != 1 {
		t.Fatalf("expected 1 fallback root, got %d", len(roots))
	}
}

func TestPrintTree(t *testing.T) {
	entries := []ProcessEntry{
		{PID: 1, PPID: 0, Comm: "init"},
		{PID: 2, PPID: 1, Comm: "bash"},
		{PID: 3, PPID: 2, Comm: "vim"},
	}
	PrintTree(entries)
}
