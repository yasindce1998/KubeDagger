// Package taskpolicy applies submission safety checks consistently across
// operator interfaces, independently of their transport and queue format.
package taskpolicy

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
)

// Policy is configured once before serving requests. Target validation is an
// input filter, not a sandbox for arbitrary commands or module behavior.
type Policy struct {
	Scope  *scope.Scope
	Events *events.Store
}

// Check must succeed before a submission enters any queue. Rejections are
// recorded without the raw payload, which may contain credentials.
func (p Policy) Check(agentID, taskType string, payload map[string]string) error {
	var err error
	auditDetail := "invalid submission"
	switch {
	case strings.TrimSpace(agentID) == "":
		err = errors.New("missing agent_id")
	case strings.TrimSpace(taskType) == "":
		err = errors.New("missing type")
	default:
		if scopeErr := p.Scope.CheckTask(taskType, payload); scopeErr != nil {
			err = fmt.Errorf("task rejected by scope policy: %w", scopeErr)
			auditDetail = "task rejected by scope policy"
		}
	}
	if err != nil {
		p.record(events.Event{
			Type: events.TypeTaskRejected, AgentID: agentID, TaskType: taskType,
			Status: "rejected", Detail: auditDetail,
		})
	}
	return err
}

// RecordSubmitted records an accepted submission after it has been queued.
func (p Policy) RecordSubmitted(agentID, taskType string, payload map[string]string) {
	p.record(events.Event{
		Type: events.TypeTaskSubmitted, AgentID: agentID, TaskType: taskType,
		Technique: payload["name"], Payload: maps.Clone(payload),
	})
}

func (p Policy) record(e events.Event) {
	if p.Events == nil {
		return
	}
	if err := p.Events.Record(e); err != nil {
		logrus.Warnf("failed to record %s event: %v", e.Type, err)
	}
}
