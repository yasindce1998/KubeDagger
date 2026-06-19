package c2server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupHandlers() *Handlers {
	agents := NewAgentRegistry()
	tasks := NewTaskQueue()
	return NewHandlers(agents, tasks)
}

func TestHandleCheckin_Valid(t *testing.T) {
	h := setupHandlers()
	req := CheckinRequest{
		AgentID:  "agent-1",
		Hostname: "host1",
		OS:       OSLinux,
		Arch:     "amd64",
		PID:      1234,
		User:     "root",
	}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/checkin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp CheckinResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SleepInterval != int(DefaultBeaconInterval.Seconds()) {
		t.Errorf("expected sleep %d, got %d", int(DefaultBeaconInterval.Seconds()), resp.SleepInterval)
	}
}

func TestHandleCheckin_InvalidMethod(t *testing.T) {
	h := setupHandlers()
	r := httptest.NewRequest(http.MethodGet, "/checkin", nil)
	w := httptest.NewRecorder()
	h.HandleCheckin(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleCheckin_InvalidJSON(t *testing.T) {
	h := setupHandlers()
	r := httptest.NewRequest(http.MethodPost, "/checkin", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleCheckin_MissingAgentID(t *testing.T) {
	h := setupHandlers()
	req := CheckinRequest{Hostname: "h1"}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/checkin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleCheckin(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleTask_NoTasks(t *testing.T) {
	h := setupHandlers()
	// Register agent first
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	req := TaskRequest{AgentID: "agent-1"}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleTask(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestHandleTask_WithTask(t *testing.T) {
	h := setupHandlers()
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})
	h.tasks.Enqueue("agent-1", TaskShell, map[string]string{"command": "id"})

	req := TaskRequest{AgentID: "agent-1"}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleTask(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp TaskResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Type != TaskShell {
		t.Errorf("expected shell task, got %s", resp.Type)
	}
	if resp.Payload["command"] != "id" {
		t.Errorf("expected command 'id', got %q", resp.Payload["command"])
	}
}

func TestHandleTask_UnknownAgent(t *testing.T) {
	h := setupHandlers()
	req := TaskRequest{AgentID: "unknown-agent"}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleTask(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleResult_Complete(t *testing.T) {
	h := setupHandlers()
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})
	task := h.tasks.Enqueue("agent-1", TaskShell, map[string]string{"command": "id"})
	h.tasks.Dequeue("agent-1")

	req := ResultRequest{
		AgentID: "agent-1",
		TaskID:  task.ID,
		Status:  StatusCompleted,
		Output:  "uid=0(root)",
	}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp ResultResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Ack {
		t.Error("expected ack=true")
	}

	completed, ok := h.tasks.Get(task.ID)
	if !ok {
		t.Fatal("task not found")
	}
	if completed.Status != StatusCompleted {
		t.Errorf("expected completed status, got %s", completed.Status)
	}
	if completed.Output != "uid=0(root)" {
		t.Errorf("expected output 'uid=0(root)', got %q", completed.Output)
	}
}

func TestHandleResult_MissingFields(t *testing.T) {
	h := setupHandlers()
	req := ResultRequest{AgentID: "agent-1"}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest(http.MethodPost, "/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleResult(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
