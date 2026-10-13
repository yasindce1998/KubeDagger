package servicemesh

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// MeshType identifies the service mesh implementation.
type MeshType string

// Service mesh type constants.
const (
	MeshCnativeMesh    MeshType = "cnative-mesh"
	MeshCnativeMeshAlt MeshType = "cnative-mesh-alt"
	MeshUnknown        MeshType = "unknown"
)

// MeshInfo holds details about a detected service mesh installation.
type MeshInfo struct {
	Type       MeshType
	Namespace  string
	Version    string
	Components []string
}

// DetectMesh probes the cluster for cnative-mesh or cnative-mesh-alt control plane components.
func DetectMesh(ctx context.Context) (*MeshInfo, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("not in cluster: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	if info := detectCnativeMesh(ctx, client); info != nil {
		return info, nil
	}

	if info := detectCnativeMeshAlt(ctx, client); info != nil {
		return info, nil
	}

	return nil, nil
}

func detectCnativeMesh(ctx context.Context, client kubernetes.Interface) *MeshInfo {
	namespaces := []string{"istio-system", "istio"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=istiod",
		})
		if err == nil && len(pods.Items) > 0 {
			info := &MeshInfo{
				Type:      MeshCnativeMesh,
				Namespace: ns,
			}
			for _, pod := range pods.Items {
				info.Components = append(info.Components, pod.Name)
				for _, c := range pod.Spec.Containers {
					if c.Name == "discovery" {
						for _, env := range c.Env {
							if env.Name == "PILOT_REVISION" {
								info.Version = env.Value
							}
						}
					}
				}
			}

			gateways, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
				LabelSelector: "app=istio-ingressgateway",
			})
			if err == nil {
				for _, gw := range gateways.Items {
					info.Components = append(info.Components, gw.Name)
				}
			}

			return info
		}
	}
	return nil
}

func detectCnativeMeshAlt(ctx context.Context, client kubernetes.Interface) *MeshInfo {
	pods, err := client.CoreV1().Pods("linkerd").List(ctx, metav1.ListOptions{
		LabelSelector: "linkerd.io/control-plane-component=destination",
	})
	if err == nil && len(pods.Items) > 0 {
		info := &MeshInfo{
			Type:      MeshCnativeMeshAlt,
			Namespace: "linkerd",
		}
		for _, pod := range pods.Items {
			info.Components = append(info.Components, pod.Name)
		}
		return info
	}
	return nil
}

// GetKubeClient returns a typed Kubernetes client from the in-cluster config.
func GetKubeClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// FormatMeshInfo returns a human-readable summary of the detected mesh and its components.
func FormatMeshInfo(info *MeshInfo) string {
	if info == nil {
		return "no service mesh detected"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Mesh: %s (namespace=%s version=%s)\n", info.Type, info.Namespace, info.Version)
	fmt.Fprintf(&sb, "Components (%d):\n", len(info.Components))
	for _, c := range info.Components {
		fmt.Fprintf(&sb, "  - %s\n", c)
	}
	return sb.String()
}
