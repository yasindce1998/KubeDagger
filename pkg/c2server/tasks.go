package c2server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type TaskQueue struct {
	mu      sync.Mutex
	pending map[string][]*Task // agent_id -> FIFO queue
	all     map[string]*Task   // task_id -> task
}

func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		pending: make(map[string][]*Task),
		all:     make(map[string]*Task),
	}
}

func (q *TaskQueue) Enqueue(agentID string, taskType TaskType, payload map[string]string) *Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	task := &Task{
		ID:        generateTaskID(),
		AgentID:   agentID,
		Type:      taskType,
		Payload:   payload,
		Status:    StatusPending,
		CreatedAt: time.Now(),
	}

	q.pending[agentID] = append(q.pending[agentID], task)
	q.all[task.ID] = task
	return task
}

func (q *TaskQueue) Dequeue(agentID string) *Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	queue := q.pending[agentID]
	if len(queue) == 0 {
		return nil
	}

	task := queue[0]
	q.pending[agentID] = queue[1:]

	now := time.Now()
	task.Status = StatusDispatched
	task.StartedAt = &now
	return task
}

func (q *TaskQueue) HasPending(agentID string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending[agentID]) > 0
}

func (q *TaskQueue) Complete(taskID string, output string, taskErr string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	task, ok := q.all[taskID]
	if !ok {
		return
	}

	now := time.Now()
	task.FinishedAt = &now
	task.Output = output

	if taskErr != "" {
		task.Status = StatusFailed
		task.Error = taskErr
	} else {
		task.Status = StatusCompleted
	}
}

func (q *TaskQueue) Get(taskID string) (*Task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	task, ok := q.all[taskID]
	if !ok {
		return nil, false
	}
	copy := *task
	return &copy, true
}

func (q *TaskQueue) ListForAgent(agentID string) []Task {
	q.mu.Lock()
	defer q.mu.Unlock()

	var result []Task
	for _, t := range q.all {
		if t.AgentID == agentID {
			result = append(result, *t)
		}
	}
	return result
}

func generateTaskID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
