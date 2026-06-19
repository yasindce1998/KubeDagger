package cicd

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDetectTekton(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := client.CoreV1().Pods("tekton-pipelines").Create(context.Background(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tekton-pipelines-controller-abc",
				Namespace: "tekton-pipelines",
				Labels:    map[string]string{"app.kubernetes.io/part-of": "tekton-pipelines"},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}

		result := detectTekton(context.Background(), client)
		if !result.Detected {
			t.Error("expected tekton to be detected")
		}
		if result.Namespace != "tekton-pipelines" {
			t.Errorf("namespace = %q, want %q", result.Namespace, "tekton-pipelines")
		}
		if len(result.Controllers) != 1 {
			t.Errorf("expected 1 controller, got %d", len(result.Controllers))
		}
	})

	t.Run("absent", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		result := detectTekton(context.Background(), client)
		if result.Detected {
			t.Error("expected tekton not detected on empty cluster")
		}
	})
}

func TestDetectArgoCD(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := client.CoreV1().Pods("argocd").Create(context.Background(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "argocd-server-xyz",
				Namespace: "argocd",
				Labels:    map[string]string{"app.kubernetes.io/part-of": "argocd"},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}

		result := detectArgoCD(context.Background(), client)
		if !result.Detected {
			t.Error("expected argocd to be detected")
		}
		if result.Namespace != "argocd" {
			t.Errorf("namespace = %q, want %q", result.Namespace, "argocd")
		}
		if len(result.Controllers) != 1 {
			t.Errorf("expected 1 controller, got %d", len(result.Controllers))
		}
	})

	t.Run("absent", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		result := detectArgoCD(context.Background(), client)
		if result.Detected {
			t.Error("expected argocd not detected on empty cluster")
		}
	})
}

func TestDetectFlux(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := client.CoreV1().Pods("flux-system").Create(context.Background(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "source-controller-abc",
				Namespace: "flux-system",
				Labels:    map[string]string{"app": "source-controller"},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}

		result := detectFlux(context.Background(), client)
		if !result.Detected {
			t.Error("expected flux to be detected")
		}
		if result.Namespace != "flux-system" {
			t.Errorf("namespace = %q, want %q", result.Namespace, "flux-system")
		}
	})

	t.Run("absent", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		result := detectFlux(context.Background(), client)
		if result.Detected {
			t.Error("expected flux not detected on empty cluster")
		}
	})
}

func TestFormatPlatforms(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		out := FormatPlatforms(nil)
		if out != "no CI/CD platforms detected" {
			t.Errorf("unexpected output: %q", out)
		}
	})

	t.Run("with platforms", func(t *testing.T) {
		platforms := []Platform{
			{Name: "tekton", Detected: true, Namespace: "tekton-pipelines", Controllers: []string{"controller-1"}},
			{Name: "argocd", Detected: true, Namespace: "argocd", Controllers: []string{"server-1", "repo-server-1"}},
		}
		out := FormatPlatforms(platforms)
		if !strings.Contains(out, "[tekton]") {
			t.Errorf("missing tekton in output: %q", out)
		}
		if !strings.Contains(out, "[argocd]") {
			t.Errorf("missing argocd in output: %q", out)
		}
	})
}
