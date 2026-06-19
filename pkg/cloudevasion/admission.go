package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// AdmissionController describes a discovered webhook admission controller.
type AdmissionController struct {
	Name     string
	Type     string
	Webhooks []string
}

// EvadeAdmissionControllers executes the specified admission controller evasion technique.
func EvadeAdmissionControllers(ctx context.Context, client kubernetes.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return enumerateWebhooks(ctx, client)
	case "bypass_labels":
		return bypassViaLabels(ctx, client)
	case "ephemeral":
		return ephemeralContainerBypass(ctx, client)
	case "static_pod":
		return staticPodBypass(ctx, client)
	default:
		return enumerateWebhooks(ctx, client)
	}
}

func enumerateWebhooks(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
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

func bypassViaLabels(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
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

func ephemeralContainerBypass(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Ephemeral Container Bypass:\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		Limit: 10,
	})
	if err != nil {
		return &EvasionResult{Technique: "ephemeral", Success: false, Output: fmt.Sprintf("failed to list pods: %v", err)}, nil
	}

	sb.WriteString("  Candidate pods for ephemeral container injection:\n")
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			fmt.Fprintf(&sb, "    %s/%s (containers: %d)\n", pod.Namespace, pod.Name, len(pod.Spec.Containers))
		}
	}

	sb.WriteString("\n  Ephemeral containers bypass:\n")
	sb.WriteString("    - Pod security policies/standards\n")
	sb.WriteString("    - Image allowlists\n")
	sb.WriteString("    - Resource quota enforcement\n")
	sb.WriteString("    - Security context constraints\n\n")
	sb.WriteString("  API: PATCH /api/v1/namespaces/<ns>/pods/<pod>/ephemeralcontainers\n")

	return &EvasionResult{
		Technique: "ephemeral",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func staticPodBypass(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Static Pod Bypass:\n\n")

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return &EvasionResult{Technique: "static_pod", Success: false, Output: fmt.Sprintf("failed to list nodes: %v", err)}, nil
	}

	sb.WriteString("  Cluster nodes (static pod targets):\n")
	for _, node := range nodes.Items {
		role := "worker"
		if _, ok := node.Labels["node-role.kubernetes.io/control-plane"]; ok {
			role = "control-plane"
		}
		fmt.Fprintf(&sb, "    %s (%s)\n", node.Name, role)
	}

	sb.WriteString("\n  Static pods bypass ALL admission controllers.\n")
	sb.WriteString("  Common manifest paths:\n")
	sb.WriteString("    - /etc/kubernetes/manifests/\n")
	sb.WriteString("    - /etc/kubelet.d/\n\n")
	sb.WriteString("  Requires write access to node filesystem via hostPath or container escape.\n")

	return &EvasionResult{
		Technique: "static_pod",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
