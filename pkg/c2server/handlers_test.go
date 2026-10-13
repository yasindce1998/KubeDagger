package c2server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/malleable"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
)

func setupHandlers() *Handlers {
	agents := NewAgentRegistry()
	tasks := NewTaskQueue()
	return NewHandlers(agents, tasks)
}

func newTestStore(t *testing.T) *events.Store {
	t.Helper()
	store, err := events.NewStore("")
	if err != nil {
		t.Fatalf("new event store: %v", err)
	}
	return store
}

func postJSON(t *testing.T, handler http.HandlerFunc, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
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

func TestHandleCheckin_EventRecorded(t *testing.T) {
	store := newTestStore(t)
	h := NewHandlers(NewAgentRegistry(), NewTaskQueue(), WithEvents(store))

	w := postJSON(t, h.HandleCheckin, "/checkin", CheckinRequest{
		AgentID:  "agent-1",
		Hostname: "h1",
		OS:       OSLinux,
		Arch:     "amd64",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	evs := store.List(0, 0)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Type != events.TypeAgentCheckin {
		t.Errorf("expected %s event, got %s", events.TypeAgentCheckin, evs[0].Type)
	}
	if evs[0].AgentID != "agent-1" {
		t.Errorf("expected agent-1, got %s", evs[0].AgentID)
	}
	if evs[0].Detail != "os=linux arch=amd64" {
		t.Errorf("unexpected detail: %q", evs[0].Detail)
	}
}

func TestHandleCheckin_ProfileSleepInterval(t *testing.T) {
	profile := &malleable.Profile{Name: "test", SleepBaseSeconds: 10, JitterPct: 20}
	h := NewHandlers(NewAgentRegistry(), NewTaskQueue(), WithProfile(profile))

	// 10s base +/- 20% jitter = [8s, 12s]
	for range 50 {
		w := postJSON(t, h.HandleCheckin, "/checkin", CheckinRequest{
			AgentID:  "agent-1",
			Hostname: "h1",
			OS:       OSLinux,
			Arch:     "amd64",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp CheckinResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.SleepInterval < 8 || resp.SleepInterval > 12 {
			t.Fatalf("sleep interval %d outside jitter bounds [8, 12]", resp.SleepInterval)
		}
	}
}

func TestHandleSubmit_Success(t *testing.T) {
	h := setupHandlers()
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	w := postJSON(t, h.HandleSubmit, SubmitAPIPath, SubmitRequest{
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: map[string]string{"command": "id"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp SubmitResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TaskID == "" {
		t.Error("expected non-empty task id")
	}
	if !h.tasks.HasPending("agent-1") {
		t.Error("expected task to be queued")
	}

	// The queued task must be dispatchable through the agent task route.
	taskResp := postJSON(t, h.HandleTask, "/task", TaskRequest{AgentID: "agent-1"})
	if taskResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from task fetch, got %d", taskResp.Code)
	}
	var tr TaskResponse
	if err := json.NewDecoder(taskResp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode task response: %v", err)
	}
	if tr.TaskID != resp.TaskID || tr.Type != TaskShell || tr.Payload["command"] != "id" {
		t.Errorf("unexpected dispatched task: %+v", tr)
	}
}

func TestHandleSubmit_Errors(t *testing.T) {
	h := setupHandlers()
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	tests := []struct {
		name     string
		method   string
		request  interface{}
		wantCode int
	}{
		{
			name:     "method not allowed",
			method:   http.MethodGet,
			request:  nil,
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:     "missing agent id",
			method:   http.MethodPost,
			request:  SubmitRequest{Type: TaskShell},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "missing type",
			method:   http.MethodPost,
			request:  SubmitRequest{AgentID: "agent-1"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "unknown agent",
			method:   http.MethodPost,
			request:  SubmitRequest{AgentID: "ghost", Type: TaskShell},
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.request)
			r := httptest.NewRequest(tt.method, SubmitAPIPath, bytes.NewReader(data))
			w := httptest.NewRecorder()
			h.HandleSubmit(w, r)

			if w.Code != tt.wantCode {
				t.Fatalf("expected %d, got %d (body: %s)", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleSubmit_ScopeRejected(t *testing.T) {
	scp := &scope.Scope{Namespaces: []string{"allowed-ns"}}
	agents := NewAgentRegistry()
	tasks := NewTaskQueue()
	h := NewHandlers(agents, tasks, WithScope(scp))
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	w := postJSON(t, h.HandleSubmit, SubmitAPIPath, SubmitRequest{
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: map[string]string{"namespace": "prod", "command": "id"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body: %s)", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "task rejected by scope policy") {
		t.Errorf("expected scope policy error, got: %s", body)
	}
	if !strings.Contains(body, "prod") {
		t.Errorf("expected violation details, got: %s", body)
	}
	if tasks.HasPending("agent-1") {
		t.Error("rejected task must not be queued")
	}
}

func TestHandleSubmit_ScopeAllows(t *testing.T) {
	scp := &scope.Scope{
		Namespaces: []string{"allowed-ns"},
		Domains:    []string{".example.com"},
	}
	h := NewHandlers(NewAgentRegistry(), NewTaskQueue(), WithScope(scp))
	h.agents.Checkin(CheckinRequest{AgentID: "agent-1", Hostname: "h1", OS: OSLinux, Arch: "amd64"})

	w := postJSON(t, h.HandleSubmit, SubmitAPIPath, SubmitRequest{
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: map[string]string{"namespace": "allowed-ns", "host": "api.example.com"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if !h.tasks.HasPending("agent-1") {
		t.Error("expected task to be queued")
	}
}

func TestTaskRoundTrip_EventsRecorded(t *testing.T) {
	store := newTestStore(t)
	h := NewHandlers(NewAgentRegistry(), NewTaskQueue(), WithEvents(store))

	// 1. Agent checks in.
	w := postJSON(t, h.HandleCheckin, "/checkin", CheckinRequest{
		AgentID:  "agent-1",
		Hostname: "h1",
		OS:       OSLinux,
		Arch:     "amd64",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("checkin: expected 200, got %d", w.Code)
	}

	// 2. Operator submits a task.
	payload := map[string]string{"command": "id", "name": "whoami-recon"}
	w = postJSON(t, h.HandleSubmit, SubmitAPIPath, SubmitRequest{
		AgentID: "agent-1",
		Type:    TaskShell,
		Payload: payload,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("submit: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var submitResp SubmitResponse
	if err := json.NewDecoder(w.Body).Decode(&submitResp); err != nil {
		t.Fatalf("decode submit response: %v", err)
	}

	// 3. Agent fetches the task.
	w = postJSON(t, h.HandleTask, "/task", TaskRequest{AgentID: "agent-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("task fetch: expected 200, got %d", w.Code)
	}
	var taskResp TaskResponse
	if err := json.NewDecoder(w.Body).Decode(&taskResp); err != nil {
		t.Fatalf("decode task response: %v", err)
	}
	if taskResp.TaskID != submitResp.TaskID {
		t.Fatalf("expected task %s, got %s", submitResp.TaskID, taskResp.TaskID)
	}

	// 4. Agent posts the result.
	w = postJSON(t, h.HandleResult, "/result", ResultRequest{
		AgentID: "agent-1",
		TaskID:  submitResp.TaskID,
		Status:  StatusCompleted,
		Output:  strings.Repeat("A", 300),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("result: expected 200, got %d", w.Code)
	}

	evs := store.List(0, 0)
	if len(evs) != 3 {
		t.Fatalf("expected 3 events, got %d", len(evs))
	}

	checkin := evs[0]
	if checkin.Type != events.TypeAgentCheckin || checkin.AgentID != "agent-1" {
		t.Errorf("unexpected checkin event: %+v", checkin)
	}

	submitted := evs[1]
	if submitted.Type != events.TypeTaskSubmitted || submitted.AgentID != "agent-1" {
		t.Errorf("unexpected submitted event: %+v", submitted)
	}
	if submitted.TaskType != string(TaskShell) {
		t.Errorf("expected task type %s, got %s", TaskShell, submitted.TaskType)
	}
	if submitted.Technique != "whoami-recon" {
		t.Errorf("expected technique from payload name, got %q", submitted.Technique)
	}
	if submitted.Payload["command"] != "id" {
		t.Errorf("expected payload recorded, got %+v", submitted.Payload)
	}

	result := evs[2]
	if result.Type != events.TypeTaskResult || result.AgentID != "agent-1" {
		t.Errorf("unexpected result event: %+v", result)
	}
	if result.TaskType != string(TaskShell) {
		t.Errorf("expected task type %s, got %q", TaskShell, result.TaskType)
	}
	if result.Status != string(StatusCompleted) {
		t.Errorf("expected status %s, got %q", StatusCompleted, result.Status)
	}
	if result.Technique != "whoami-recon" {
		t.Errorf("expected technique from payload name, got %q", result.Technique)
	}
	if len(result.Detail) != maxResultDetail {
		t.Errorf("expected detail truncated to %d chars, got %d", maxResultDetail, len(result.Detail))
	}
}
