package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/webhook"
)

type WebhookDeploy struct{}

func (m *WebhookDeploy) Name() string      { return "webhook_deploy" }
func (m *WebhookDeploy) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *WebhookDeploy) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "status"
	}

	switch action {
	case "generate_certs":
		return m.generateCerts(args)
	case "status":
		return m.status()
	default:
		return nil, fmt.Errorf("unknown action: %s (valid: generate_certs, status)", action)
	}
}

func (m *WebhookDeploy) generateCerts(args map[string]string) (*Result, error) {
	service := args["service"]
	if service == "" {
		service = "kubedagger-webhook"
	}
	namespace := args["namespace"]
	if namespace == "" {
		namespace = "default"
	}

	bundle, err := webhook.GenerateCerts(service, namespace)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("cert generation failed: %v", err),
		}, nil
	}

	var summary []string
	summary = append(summary, fmt.Sprintf("service: %s", service))
	summary = append(summary, fmt.Sprintf("namespace: %s", namespace))
	summary = append(summary, fmt.Sprintf("ca_cert_size: %d bytes", len(bundle.CACertPEM)))
	summary = append(summary, fmt.Sprintf("server_cert_size: %d bytes", len(bundle.ServerCertPEM)))
	summary = append(summary, fmt.Sprintf("server_key_size: %d bytes", len(bundle.ServerKeyPEM)))
	summary = append(summary, "status: certs generated successfully")

	return &Result{
		Success: true,
		Output:  strings.Join(summary, "\n"),
	}, nil
}

func (m *WebhookDeploy) status() (*Result, error) {
	return &Result{
		Success: true,
		Output:  "webhook deployment module ready\ncapabilities: generate_certs, install (requires in-cluster)",
	}, nil
}
