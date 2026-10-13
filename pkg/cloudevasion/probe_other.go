//go:build !linux

package cloudevasion

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func detectCnativeProbe(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kube-system", "cilium", "tetragon"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=tetragon",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cnative-probe",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d cnative-probe agent pods", len(pods.Items)),
			}}
		}
	}
	return nil
}

// EvadeCnativeProbe is a stub on non-Linux platforms.
func EvadeCnativeProbe(_ context.Context, _ kubernetes.Interface, _ dynamic.Interface, technique string) (*EvasionResult, error) {
	return &EvasionResult{
		Technique: technique,
		Success:   false,
		Output:    "cnative-probe evasion requires Linux (eBPF/io_uring not available on this platform)",
	}, nil
}

// DisruptCnativeProbe is a stub on non-Linux platforms.
func DisruptCnativeProbe(_ context.Context, _ kubernetes.Interface) (*EvasionResult, error) {
	return &EvasionResult{
		Technique: "disrupt_cnative_probe",
		Success:   false,
		Output:    "cnative-probe disruption requires Linux",
	}, nil
}
