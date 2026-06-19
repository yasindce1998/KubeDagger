package c2server

import (
	"testing"
	"time"
)

func TestAgentRegistry_CheckinNew(t *testing.T) {
	r := NewAgentRegistry()
	req := CheckinRequest{
		AgentID:  "test-1",
		Hostname: "host1",
		OS:       OSLinux,
		Arch:     "amd64",
		PID:      100,
		User:     "user1",
	}

	info := r.Checkin(req)
	if info.ID != "test-1" {
		t.Errorf("expected ID test-1, got %s", info.ID)
	}
	if !info.Alive {
		t.Error("expected alive=true")
	}
	if info.Hostname != "host1" {
		t.Errorf("expected hostname host1, got %s", info.Hostname)
	}
}

func TestAgentRegistry_CheckinExisting(t *testing.T) {
	r := NewAgentRegistry()
	req := CheckinRequest{AgentID: "test-1", Hostname: "host1", OS: OSLinux, Arch: "amd64"}

	r.Checkin(req)
	req.Hostname = "host2"
	info := r.Checkin(req)

	if info.Hostname != "host2" {
		t.Errorf("expected hostname updated to host2, got %s", info.Hostname)
	}
}

func TestAgentRegistry_Get(t *testing.T) {
	r := NewAgentRegistry()
	r.Checkin(CheckinRequest{AgentID: "test-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	info, ok := r.Get("test-1")
	if !ok {
		t.Fatal("expected to find agent")
	}
	if info.ID != "test-1" {
		t.Errorf("expected test-1, got %s", info.ID)
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestAgentRegistry_List(t *testing.T) {
	r := NewAgentRegistry()
	r.Checkin(CheckinRequest{AgentID: "a1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})
	r.Checkin(CheckinRequest{AgentID: "a2", Hostname: "h2", OS: OSWindows, Arch: "amd64"})

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(list))
	}
}

func TestAgentRegistry_Remove(t *testing.T) {
	r := NewAgentRegistry()
	r.Checkin(CheckinRequest{AgentID: "a1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})
	r.Remove("a1")

	_, ok := r.Get("a1")
	if ok {
		t.Error("expected agent to be removed")
	}
}

func TestAgentRegistry_MarkDead(t *testing.T) {
	r := NewAgentRegistry()
	req := CheckinRequest{AgentID: "a1", Hostname: "h1", OS: OSLinux, Arch: "amd64"}
	r.Checkin(req)

	// Manually set LastSeen far in the past
	r.mu.Lock()
	r.agents["a1"].LastSeen = time.Now().Add(-5 * time.Minute)
	r.mu.Unlock()

	r.markDead()

	info, _ := r.Get("a1")
	if info.Alive {
		t.Error("expected agent to be marked dead")
	}
}
