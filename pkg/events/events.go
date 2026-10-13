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

// Package events provides a structured, append-only record of agent and task
// activity on the C2 server. Events are kept in an in-memory ring buffer and
// can optionally be persisted as JSON lines for later analysis, report
// generation, and SIEM ingestion.
package events

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event types emitted by the C2 server.
const (
	TypeAgentCheckin  = "agent_checkin"
	TypeTaskSubmitted = "task_submitted"
	TypeTaskResult    = "task_result"
)

// Event is a single structured telemetry record.
type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	AgentID   string            `json:"agent_id,omitempty"`
	Type      string            `json:"type"`
	Technique string            `json:"technique,omitempty"`
	TaskType  string            `json:"task_type,omitempty"`
	Status    string            `json:"status,omitempty"`
	MITRE     string            `json:"mitre,omitempty"`
	Detail    string            `json:"detail,omitempty"`
	Payload   map[string]string `json:"payload,omitempty"`
}

// Store keeps events in memory and optionally appends them to a JSONL file.
// It is safe for concurrent use.
type Store struct {
	mu   sync.RWMutex
	ring []Event
	max  int
	seq  int
	file *os.File
}

// NewStore creates an event store. If path is non-empty, events are appended
// to that file as JSON lines (created if missing, parent directories are NOT
// created). If path is empty, the store is memory-only.
func NewStore(path string) (*Store, error) {
	s := &Store{max: 10000}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("events: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("events: open file: %w", err)
	}
	s.file = f
	return s, nil
}

// Record appends an event to the store. ID and Timestamp are assigned when
// empty. Record never fails for memory-only stores; file append failures are
// returned but the event is still kept in memory.
func (s *Store) Record(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", s.seq)
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	s.ring = append(s.ring, e)
	if len(s.ring) > s.max {
		s.ring = s.ring[len(s.ring)-s.max:]
	}

	if s.file != nil {
		data, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("events: marshal: %w", err)
		}
		if _, err := s.file.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("events: write: %w", err)
		}
	}
	return nil
}

// List returns up to limit events starting at offset (oldest first).
// A limit of 0 or less means all remaining events.
func (s *Store) List(offset, limit int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if offset < 0 {
		offset = 0
	}
	if offset >= len(s.ring) {
		return nil
	}
	out := s.ring[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}

	cp := make([]Event, len(out))
	copy(cp, out)
	return cp
}

// Count returns the number of events currently held in memory.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ring)
}

// Close closes the underlying file, if any.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}
