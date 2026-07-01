//go:build !linux

package cloudevasion

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func detectTetragon(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kube-system", "cilium", "tetragon"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=tetragon",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "tetragon",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d tetragon agent pods", len(pods.Items)),
			}}
		}
	}
	return nil
}

// EvadeTetragon is a stub on non-Linux platforms.
func EvadeTetragon(_ context.Context, _ kubernetes.Interface, _ dynamic.Interface, technique string) (*EvasionResult, error) {
	return &EvasionResult{
		Technique: technique,
		Success:   false,
		Output:    "Tetragon evasion requires Linux (eBPF/io_uring not available on this platform)",
	}, nil
}

// DisruptTetragon is a stub on non-Linux platforms.
func DisruptTetragon(_ context.Context, _ kubernetes.Interface) (*EvasionResult, error) {
	return &EvasionResult{
		Technique: "disrupt_tetragon",
		Success:   false,
		Output:    "Tetragon disruption requires Linux",
	}, nil
}
