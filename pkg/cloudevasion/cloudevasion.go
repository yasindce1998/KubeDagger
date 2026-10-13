package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// DetectionSystem represents a runtime security tool detected in the cluster.
type DetectionSystem struct {
	Name      string
	Detected  bool
	Namespace string
	Details   string
}

// EvasionResult holds the outcome of an evasion technique execution.
type EvasionResult struct {
	Technique string
	Success   bool
	Output    string
}

// DetectSystems enumerates runtime security tools deployed in the cluster.
func DetectSystems(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) ([]DetectionSystem, error) {
	var systems []DetectionSystem

	systems = append(systems, detectCnativeSensor(ctx, client)...)
	systems = append(systems, detectCnativeAuthz(ctx, client)...)
	systems = append(systems, detectCnativePolicy(ctx, client)...)
	systems = append(systems, detectCnativeScanner(ctx, client)...)
	systems = append(systems, detectCnativeMonitor(ctx, client)...)
	systems = append(systems, detectCnativeProbe(ctx, client)...)
	systems = append(systems, detectCnativeShield(ctx, client)...)
	systems = append(systems, detectCnativeAudit(ctx, client)...)
	systems = append(systems, detectCnativeResponder(ctx, client)...)
	systems = append(systems, detectCnativeCerts(ctx, client)...)
	systems = append(systems, detectCnativeMesh(ctx, client, dynClient)...)
	systems = append(systems, detectCnativeIdentity(ctx, client, dynClient)...)
	systems = append(systems, detectCnativeNet(ctx, client)...)
	systems = append(systems, detectCnativeRegistry(ctx, client)...)
	systems = append(systems, detectCnativeSigning(ctx, client, dynClient)...)
	systems = append(systems, detectCnativeBackup(ctx, client)...)
	systems = append(systems, detectCnativeSecrets(ctx, client)...)
	systems = append(systems, detectCnativeControl(ctx, client)...)
	systems = append(systems, detectCnativeServerless(ctx, client)...)
	systems = append(systems, detectCnativeWorkflow(ctx, client)...)

	return systems, nil
}

func detectCnativeSensor(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"falco", "falco-system", "security"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=falco",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cnative-sensor",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d pods running", len(pods.Items)),
			}}
		}
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=falco",
	})
	if err == nil && len(pods.Items) > 0 {
		return []DetectionSystem{{
			Name:      "cnative-sensor",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("%d pods across namespaces", len(pods.Items)),
		}}
	}

	return nil
}

func detectCnativeAuthz(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"opa", "gatekeeper-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				if strings.Contains(pod.Name, "gatekeeper") || strings.Contains(pod.Name, "opa") {
					return []DetectionSystem{{
						Name:      "cnative-authz",
						Detected:  true,
						Namespace: ns,
						Details:   "cnative-authz admission controller",
					}}
				}
			}
		}
	}
	return nil
}

func detectCnativePolicy(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kyverno", "kyverno-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=kyverno",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cnative-policy",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d cnative-policy pods", len(pods.Items)),
			}}
		}
	}
	return nil
}

func detectCnativeScanner(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"trivy-system", "trivy"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=trivy-operator",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cnative-scanner",
				Detected:  true,
				Namespace: ns,
				Details:   "cnative-scanner vulnerability scanner operator",
			}}
		}
	}
	return nil
}

func detectCnativeMonitor(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=sysdig-agent",
	})
	if err == nil && len(pods.Items) > 0 {
		return []DetectionSystem{{
			Name:      "cnative-monitor",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("%d cnative-monitor agents (DaemonSet)", len(pods.Items)),
		}}
	}
	return nil
}

// GetKubeClient returns a Kubernetes client configured from in-cluster credentials.
func GetKubeClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// FormatSystems renders detected security systems as a human-readable report.
func FormatSystems(systems []DetectionSystem) string {
	if len(systems) == 0 {
		return "No detection systems found in cluster"
	}

	var sb strings.Builder
	sb.WriteString("Detection Systems:\n")
	for _, s := range systems {
		status := "not detected"
		if s.Detected {
			status = "ACTIVE"
		}
		fmt.Fprintf(&sb, "  [%s] %s (ns=%s) — %s\n", status, s.Name, s.Namespace, s.Details)
	}
	return sb.String()
}
