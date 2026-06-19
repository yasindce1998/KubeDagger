package testutil

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewFakeKubeClient(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
	}
	client := NewFakeKubeClient(pod)

	got, err := client.CoreV1().Pods("default").Get(context.Background(), "test-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get pod: %v", err)
	}
	if got.Name != "test-pod" {
		t.Errorf("name = %q, want %q", got.Name, "test-pod")
	}
}

func TestNewFakeDynamicClient(t *testing.T) {
	obj := NewUnstructured("networking.istio.io", "v1alpha3", "EnvoyFilter", "istio-system", "test-filter")
	client := NewFakeDynamicClient(obj)
	if client == nil {
		t.Fatal("expected non-nil dynamic client")
	}
}

func TestNewUnstructured(t *testing.T) {
	obj := NewUnstructured("apps", "v1", "Deployment", "prod", "my-deploy")
	if obj.GetName() != "my-deploy" {
		t.Errorf("name = %q, want %q", obj.GetName(), "my-deploy")
	}
	if obj.GetNamespace() != "prod" {
		t.Errorf("namespace = %q, want %q", obj.GetNamespace(), "prod")
	}
	gvk := obj.GroupVersionKind()
	if gvk.Group != "apps" || gvk.Version != "v1" || gvk.Kind != "Deployment" {
		t.Errorf("GVK = %v, want apps/v1/Deployment", gvk)
	}
}
