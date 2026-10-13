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

package c2server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/kubedagger/c2"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
)

func newTestMgmt(t *testing.T, opts ...MgmtOption) (*MgmtServer, *AgentRegistry, *TaskQueue) {
	t.Helper()

	key, err := c2.DeriveKey("test-mgmt-key")
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	agents := NewAgentRegistry()
	tasks := NewTaskQueue()

	m, err := NewMgmtServer(key, agents, tasks, opts...)
	if err != nil {
		t.Fatalf("new mgmt server: %v", err)
	}
	return m, agents, tasks
}

func mgmtCommand(t *testing.T, m *MgmtServer, cmd MgmtCommand) MgmtResponse {
	t.Helper()

	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}
	out, err := m.handleCommand(data)
	if err != nil {
		t.Fatalf("handle command: %v", err)
	}

	var resp MgmtResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

func TestMgmtQueueTask(t *testing.T) {
	m, agents, tasks := newTestMgmt(t)
	agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	resp := mgmtCommand(t, m, MgmtCommand{
		Action:  "queue",
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: map[string]string{"command": "id"},
	})

	if resp.Status != "ok" {
		t.Fatalf("expected ok, got %q (error: %s)", resp.Status, resp.Error)
	}
	if !tasks.HasPending("agent-1") {
		t.Error("expected task to be queued")
	}
}

func TestMgmtQueueTask_ScopeRejected(t *testing.T) {
	scp := &scope.Scope{Namespaces: []string{"allowed-ns"}}
	m, agents, tasks := newTestMgmt(t, WithMgmtScope(scp))
	agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	resp := mgmtCommand(t, m, MgmtCommand{
		Action:  "queue",
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: map[string]string{"namespace": "prod", "command": "id"},
	})

	if resp.Status != "error" {
		t.Fatalf("expected error status, got %q", resp.Status)
	}
	if !strings.Contains(resp.Error, "task rejected by scope policy") {
		t.Errorf("expected scope policy error, got: %s", resp.Error)
	}
	if !strings.Contains(resp.Error, "prod") {
		t.Errorf("expected violation details, got: %s", resp.Error)
	}
	if tasks.HasPending("agent-1") {
		t.Error("rejected task must not be queued")
	}
}

func TestMgmtQueueTask_ScopeAllows(t *testing.T) {
	scp := &scope.Scope{Namespaces: []string{"allowed-ns"}}
	m, agents, tasks := newTestMgmt(t, WithMgmtScope(scp))
	agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	resp := mgmtCommand(t, m, MgmtCommand{
		Action:  "queue",
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: map[string]string{"namespace": "allowed-ns", "command": "id"},
	})

	if resp.Status != "ok" {
		t.Fatalf("expected ok, got %q (error: %s)", resp.Status, resp.Error)
	}
	if !tasks.HasPending("agent-1") {
		t.Error("expected task to be queued")
	}
}

func TestMgmtQueueTask_EventsRecorded(t *testing.T) {
	store := newTestStore(t)
	m, agents, _ := newTestMgmt(t, WithMgmtEvents(store))
	agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	payload := map[string]string{"command": "id", "name": "whoami-recon"}
	resp := mgmtCommand(t, m, MgmtCommand{
		Action:  "queue",
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: payload,
	})
	if resp.Status != "ok" {
		t.Fatalf("expected ok, got %q (error: %s)", resp.Status, resp.Error)
	}

	evs := store.List(0, 0)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Type != events.TypeTaskSubmitted {
		t.Errorf("expected %s event, got %s", events.TypeTaskSubmitted, ev.Type)
	}
	if ev.AgentID != "agent-1" || ev.TaskType != string(TaskShell) {
		t.Errorf("unexpected event agent/task: %s/%s", ev.AgentID, ev.TaskType)
	}
	if ev.Technique != "whoami-recon" {
		t.Errorf("expected technique from payload name, got %q", ev.Technique)
	}
	if ev.Payload["command"] != "id" {
		t.Errorf("expected payload recorded, got %+v", ev.Payload)
	}
}
