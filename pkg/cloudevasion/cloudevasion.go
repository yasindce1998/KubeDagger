package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type DetectionSystem struct {
	Name      string
	Detected  bool
	Namespace string
	Details   string
}

type EvasionResult struct {
	Technique string
	Success   bool
	Output    string
}

func DetectSystems(ctx context.Context) ([]DetectionSystem, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("not in cluster: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	var systems []DetectionSystem

	systems = append(systems, detectFalco(ctx, client)...)
	systems = append(systems, detectOPA(ctx, client)...)
	systems = append(systems, detectKyverno(ctx, client)...)
	systems = append(systems, detectTrivy(ctx, client)...)
	systems = append(systems, detectSysdig(ctx, client)...)

	return systems, nil
}

func detectFalco(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"falco", "falco-system", "security"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=falco",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "falco",
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
			Name:      "falco",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("%d pods across namespaces", len(pods.Items)),
		}}
	}

	return nil
}

func detectOPA(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"opa", "gatekeeper-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				if strings.Contains(pod.Name, "gatekeeper") || strings.Contains(pod.Name, "opa") {
					return []DetectionSystem{{
						Name:      "opa-gatekeeper",
						Detected:  true,
						Namespace: ns,
						Details:   "OPA Gatekeeper admission controller",
					}}
				}
			}
		}
	}
	return nil
}

func detectKyverno(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kyverno", "kyverno-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=kyverno",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "kyverno",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d kyverno pods", len(pods.Items)),
			}}
		}
	}
	return nil
}

func detectTrivy(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"trivy-system", "trivy"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=trivy-operator",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "trivy-operator",
				Detected:  true,
				Namespace: ns,
				Details:   "Trivy vulnerability scanner operator",
			}}
		}
	}
	return nil
}

func detectSysdig(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=sysdig-agent",
	})
	if err == nil && len(pods.Items) > 0 {
		return []DetectionSystem{{
			Name:      "sysdig",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("%d sysdig agents (DaemonSet)", len(pods.Items)),
		}}
	}
	return nil
}

func GetKubeClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

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
