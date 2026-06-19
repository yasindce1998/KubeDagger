package multicluster

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDiscoverFromSecrets(t *testing.T) {
	kubeconfigYAML := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://remote-cluster:6443
  name: remote
contexts:
- context:
    cluster: remote
    user: admin
  name: remote
current-context: remote
users:
- name: admin
  user:
    token: secret-token-123`

	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-creds", Namespace: "default"},
			Data:       map[string][]byte{"kubeconfig": []byte(kubeconfigYAML)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "default"},
			Data:       map[string][]byte{"password": []byte("not-a-kubeconfig")},
		},
	)

	sources, err := DiscoverFromSecrets(context.Background(), client, "default")
	if err != nil {
		t.Fatalf("DiscoverFromSecrets: %v", err)
	}

	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}

	src := sources[0]
	if src.Type != "secret" {
		t.Errorf("type = %q, want %q", src.Type, "secret")
	}
	if len(src.Clusters) == 0 {
		t.Fatal("no clusters extracted from secret")
	}
	if src.Clusters[0].Server != "https://remote-cluster:6443" {
		t.Errorf("server = %q, want %q", src.Clusters[0].Server, "https://remote-cluster:6443")
	}
}

func TestDiscoverFromSecretsNoKubeconfigs(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "random", Namespace: "default"},
			Data:       map[string][]byte{"key": []byte("value")},
		},
	)

	sources, err := DiscoverFromSecrets(context.Background(), client, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestDiscoverFromConfigMaps(t *testing.T) {
	kubeconfigYAML := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://staging:6443
  name: staging
contexts:
- context:
    cluster: staging
    user: deployer
  name: staging
current-context: staging
users:
- name: deployer
  user:
    token: deploy-token`

	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-config", Namespace: "kube-system"},
			Data:       map[string]string{"admin.conf": kubeconfigYAML},
		},
	)

	sources, err := DiscoverFromConfigMaps(context.Background(), client, "kube-system")
	if err != nil {
		t.Fatalf("DiscoverFromConfigMaps: %v", err)
	}

	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}

	src := sources[0]
	if src.Type != "configmap" {
		t.Errorf("type = %q, want %q", src.Type, "configmap")
	}
	if len(src.Clusters) == 0 {
		t.Fatal("no clusters extracted from configmap")
	}
	if src.Clusters[0].Server != "https://staging:6443" {
		t.Errorf("server = %q, want %q", src.Clusters[0].Server, "https://staging:6443")
	}
}

func TestDiscoverFromConfigMapsEmpty(t *testing.T) {
	client := fake.NewSimpleClientset()

	sources, err := DiscoverFromConfigMaps(context.Background(), client, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestIsKubeconfigData(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "valid kubeconfig",
			data: "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://x:6443\n  name: x",
			want: true,
		},
		{
			name: "not kubeconfig",
			data: "just some random text",
			want: false,
		},
		{
			name: "partial match missing server",
			data: "apiVersion: v1\nclusters:\n- name: x",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isKubeconfigData([]byte(tt.data))
			if got != tt.want {
				t.Errorf("isKubeconfigData(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}
