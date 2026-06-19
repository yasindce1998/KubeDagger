package servicemesh

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDetectIstio(t *testing.T) {
	client := fake.NewSimpleClientset()
	_, err := client.CoreV1().Pods("istio-system").Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "istiod-abc123",
			Namespace: "istio-system",
			Labels:    map[string]string{"app": "istiod"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "discovery",
					Env: []corev1.EnvVar{
						{Name: "PILOT_REVISION", Value: "1.20"},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	info := detectIstio(context.Background(), client)
	if info == nil {
		t.Fatal("expected istio to be detected")
	}
	if info.Type != MeshIstio {
		t.Errorf("type = %q, want %q", info.Type, MeshIstio)
	}
	if info.Namespace != "istio-system" {
		t.Errorf("namespace = %q, want %q", info.Namespace, "istio-system")
	}
	if info.Version != "1.20" {
		t.Errorf("version = %q, want %q", info.Version, "1.20")
	}
	if len(info.Components) == 0 {
		t.Error("expected at least one component")
	}
}

func TestDetectIstioNotPresent(t *testing.T) {
	client := fake.NewSimpleClientset()
	info := detectIstio(context.Background(), client)
	if info != nil {
		t.Errorf("expected nil for empty cluster, got %+v", info)
	}
}

func TestDetectLinkerd(t *testing.T) {
	client := fake.NewSimpleClientset()
	_, err := client.CoreV1().Pods("linkerd").Create(context.Background(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "linkerd-destination-abc",
			Namespace: "linkerd",
			Labels:    map[string]string{"linkerd.io/control-plane-component": "destination"},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	info := detectLinkerd(context.Background(), client)
	if info == nil {
		t.Fatal("expected linkerd to be detected")
	}
	if info.Type != MeshLinkerd {
		t.Errorf("type = %q, want %q", info.Type, MeshLinkerd)
	}
	if info.Namespace != "linkerd" {
		t.Errorf("namespace = %q, want %q", info.Namespace, "linkerd")
	}
}

func TestDetectLinkerdNotPresent(t *testing.T) {
	client := fake.NewSimpleClientset()
	info := detectLinkerd(context.Background(), client)
	if info != nil {
		t.Errorf("expected nil for empty cluster, got %+v", info)
	}
}

func TestFormatMeshInfo(t *testing.T) {
	tests := []struct {
		name     string
		info     *MeshInfo
		contains string
	}{
		{
			name:     "nil info",
			info:     nil,
			contains: "no service mesh detected",
		},
		{
			name: "istio info",
			info: &MeshInfo{
				Type:       MeshIstio,
				Namespace:  "istio-system",
				Version:    "1.20",
				Components: []string{"istiod-abc", "istio-ingressgateway-xyz"},
			},
			contains: "istio",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := FormatMeshInfo(tt.info)
			if !strings.Contains(out, tt.contains) {
				t.Errorf("output %q missing %q", out, tt.contains)
			}
		})
	}
}
