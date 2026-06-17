package c2server

import "time"

type AgentOS string

const (
	OSLinux   AgentOS = "linux"
	OSWindows AgentOS = "windows"
	OSDarwin  AgentOS = "darwin"
)

type TaskType string

const (
	TaskShell    TaskType = "shell"
	TaskUpload   TaskType = "upload"
	TaskDownload TaskType = "download"
	TaskModule   TaskType = "module"
	TaskConfig   TaskType = "config"
	TaskExit     TaskType = "exit"
)

type TaskStatus string

const (
	StatusPending    TaskStatus = "pending"
	StatusDispatched TaskStatus = "dispatched"
	StatusRunning    TaskStatus = "running"
	StatusCompleted  TaskStatus = "completed"
	StatusFailed     TaskStatus = "failed"
	StatusTimeout    TaskStatus = "timeout"
)

type CheckinRequest struct {
	AgentID   string  `json:"agent_id"`
	Hostname  string  `json:"hostname"`
	OS        AgentOS `json:"os"`
	Arch      string  `json:"arch"`
	PID       int     `json:"pid"`
	User      string  `json:"user"`
	Integrity string  `json:"integrity"`
}

type CheckinResponse struct {
	SleepInterval int  `json:"sleep_interval"`
	TasksPending  bool `json:"tasks_pending"`
}

type TaskRequest struct {
	AgentID string `json:"agent_id"`
}

type TaskResponse struct {
	TaskID  string            `json:"task_id"`
	Type    TaskType          `json:"type"`
	Payload map[string]string `json:"payload"`
}

type ResultRequest struct {
	AgentID string     `json:"agent_id"`
	TaskID  string     `json:"task_id"`
	Status  TaskStatus `json:"status"`
	Output  string     `json:"output"`
	Error   string     `json:"error,omitempty"`
}

type ResultResponse struct {
	Ack bool `json:"ack"`
}

type AgentInfo struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	OS        AgentOS   `json:"os"`
	Arch      string    `json:"arch"`
	PID       int       `json:"pid"`
	User      string    `json:"user"`
	Integrity string    `json:"integrity"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Alive     bool      `json:"alive"`
}

type Task struct {
	ID         string            `json:"id"`
	AgentID    string            `json:"agent_id"`
	Type       TaskType          `json:"type"`
	Payload    map[string]string `json:"payload"`
	Status     TaskStatus        `json:"status"`
	Output     string            `json:"output"`
	Error      string            `json:"error,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	StartedAt  *time.Time        `json:"started_at,omitempty"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
}
