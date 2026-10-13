/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMemoryStore(t *testing.T) {
	s, err := NewStore("")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := s.Record(Event{Type: TypeTaskSubmitted, Technique: "sa_token"}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	if s.Count() != 5 {
		t.Fatalf("Count = %d, want 5", s.Count())
	}

	all := s.List(0, 0)
	if len(all) != 5 {
		t.Fatalf("List(0,0) = %d events, want 5", len(all))
	}
	if all[0].ID == "" || all[0].Timestamp.IsZero() {
		t.Fatal("Record must assign ID and Timestamp")
	}
	if all[0].ID == all[1].ID {
		t.Fatal("IDs must be unique")
	}
}

func TestStoreListOffsetLimit(t *testing.T) {
	s, _ := NewStore("")
	for i := 0; i < 10; i++ {
		_ = s.Record(Event{Type: TypeAgentCheckin})
	}

	got := s.List(8, 0)
	if len(got) != 2 {
		t.Fatalf("List(8,0) = %d, want 2", len(got))
	}
	got = s.List(0, 3)
	if len(got) != 3 {
		t.Fatalf("List(0,3) = %d, want 3", len(got))
	}
	if got := s.List(100, 0); got != nil {
		t.Fatalf("List(100,0) = %v, want nil", got)
	}
	if got := s.List(-5, 0); len(got) != 10 {
		t.Fatalf("List(-5,0) = %d, want 10 (negative offset clamps)", len(got))
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ts := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	_ = s.Record(Event{
		ID:        "evt-1",
		Timestamp: ts,
		AgentID:   "agent-abc",
		Type:      TypeTaskResult,
		Technique: "cloud_evasion",
		Status:    "completed",
		MITRE:     "T1562.001",
	})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open jsonl: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected one JSON line")
	}
	var e Event
	if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.AgentID != "agent-abc" || e.Type != TypeTaskResult || e.Technique != "cloud_evasion" || e.MITRE != "T1562.001" {
		t.Fatalf("round-trip mismatch: %+v", e)
	}
	if !e.Timestamp.Equal(ts) {
		t.Fatalf("timestamp mismatch: %v", e.Timestamp)
	}
}

func TestStoreConcurrent(t *testing.T) {
	s, _ := NewStore("")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Record(Event{Type: TypeAgentCheckin})
			_ = s.Count()
			_ = s.List(0, 5)
		}()
	}
	wg.Wait()
	if s.Count() != 20 {
		t.Fatalf("Count = %d after 20 concurrent records, want 20", s.Count())
	}
}

func TestRingCap(t *testing.T) {
	s, _ := NewStore("")
	s.max = 5
	for i := 0; i < 12; i++ {
		_ = s.Record(Event{Type: TypeAgentCheckin, Detail: "n"})
	}
	if s.Count() != 5 {
		t.Fatalf("Count = %d, want ring cap 5", s.Count())
	}
}
