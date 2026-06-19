package multicluster

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// KubeconfigSource represents a discovered kubeconfig and where it was found.
type KubeconfigSource struct {
	Path     string
	Type     string // "file", "env", "secret", "configmap", "incluster"
	Clusters []ClusterInfo
}

// ClusterInfo holds connection details for a discovered Kubernetes cluster.
type ClusterInfo struct {
	Name   string
	Server string
	CAData []byte
	Token  string
}

// DiscoverKubeconfigs scans the environment for kubeconfig files and credentials.
func DiscoverKubeconfigs(ctx context.Context) ([]KubeconfigSource, error) {
	var sources []KubeconfigSource

	if src, err := discoverFromEnv(); err == nil && len(src.Clusters) > 0 {
		sources = append(sources, *src)
	}

	for _, path := range kubeconfigSearchPaths() {
		if src, err := discoverFromFile(path); err == nil && len(src.Clusters) > 0 {
			sources = append(sources, *src)
		}
	}

	if src, err := discoverInCluster(); err == nil && len(src.Clusters) > 0 {
		sources = append(sources, *src)
	}

	return sources, nil
}

// DiscoverFromSecrets extracts kubeconfig data from Kubernetes secrets in the given namespace.
func DiscoverFromSecrets(ctx context.Context, client kubernetes.Interface, namespace string) ([]KubeconfigSource, error) {
	var sources []KubeconfigSource

	secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	for _, secret := range secrets.Items {
		for key, data := range secret.Data {
			if isKubeconfigData(data) {
				src, err := parseKubeconfigBytes(data)
				if err != nil {
					continue
				}
				src.Path = fmt.Sprintf("secret/%s/%s/%s", namespace, secret.Name, key)
				src.Type = "secret"
				sources = append(sources, *src)
			}
		}
	}

	return sources, nil
}

// DiscoverFromConfigMaps extracts kubeconfig data from ConfigMaps in the given namespace.
func DiscoverFromConfigMaps(ctx context.Context, client kubernetes.Interface, namespace string) ([]KubeconfigSource, error) {
	var sources []KubeconfigSource

	cms, err := client.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list configmaps: %w", err)
	}

	for _, cm := range cms.Items {
		for key, data := range cm.Data {
			if isKubeconfigData([]byte(data)) {
				src, err := parseKubeconfigBytes([]byte(data))
				if err != nil {
					continue
				}
				src.Path = fmt.Sprintf("configmap/%s/%s/%s", namespace, cm.Name, key)
				src.Type = "configmap"
				sources = append(sources, *src)
			}
		}
	}

	return sources, nil
}

func discoverFromEnv() (*KubeconfigSource, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		return nil, fmt.Errorf("KUBECONFIG not set")
	}

	paths := filepath.SplitList(kubeconfig)
	var allClusters []ClusterInfo

	for _, p := range paths {
		src, err := discoverFromFile(p)
		if err != nil {
			continue
		}
		allClusters = append(allClusters, src.Clusters...)
	}

	return &KubeconfigSource{
		Path:     kubeconfig,
		Type:     "env",
		Clusters: allClusters,
	}, nil
}

func discoverFromFile(path string) (*KubeconfigSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	src, err := parseKubeconfigBytes(data)
	if err != nil {
		return nil, err
	}
	src.Path = path
	src.Type = "file"
	return src, nil
}

func discoverInCluster() (*KubeconfigSource, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	cluster := ClusterInfo{
		Name:   "incluster",
		Server: config.Host,
	}

	if config.BearerToken != "" {
		cluster.Token = config.BearerToken
	} else if config.BearerTokenFile != "" {
		token, err := os.ReadFile(config.BearerTokenFile)
		if err == nil {
			cluster.Token = strings.TrimSpace(string(token))
		}
	}

	if config.TLSClientConfig.CAData != nil {
		cluster.CAData = config.TLSClientConfig.CAData
	} else if config.TLSClientConfig.CAFile != "" {
		ca, err := os.ReadFile(config.TLSClientConfig.CAFile)
		if err == nil {
			cluster.CAData = ca
		}
	}

	return &KubeconfigSource{
		Path:     "/var/run/secrets/kubernetes.io/serviceaccount",
		Type:     "incluster",
		Clusters: []ClusterInfo{cluster},
	}, nil
}

func parseKubeconfigBytes(data []byte) (*KubeconfigSource, error) {
	config, err := clientcmd.Load(data)
	if err != nil {
		return nil, err
	}

	return extractClusters(config)
}

func extractClusters(config *clientcmdapi.Config) (*KubeconfigSource, error) {
	var clusters []ClusterInfo

	for name, cluster := range config.Clusters {
		info := ClusterInfo{
			Name:   name,
			Server: cluster.Server,
			CAData: cluster.CertificateAuthorityData,
		}

		for _, authInfo := range config.AuthInfos {
			if authInfo.Token != "" {
				info.Token = authInfo.Token
				break
			}
			if authInfo.TokenFile != "" {
				token, err := os.ReadFile(authInfo.TokenFile)
				if err == nil {
					info.Token = strings.TrimSpace(string(token))
				}
				break
			}
		}

		clusters = append(clusters, info)
	}

	return &KubeconfigSource{Clusters: clusters}, nil
}

func kubeconfigSearchPaths() []string {
	paths := []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
	}

	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".kube", "config"))
	}

	paths = append(paths,
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/kubelet.conf",
		"/etc/rancher/k3s/k3s.yaml",
		"/root/.kube/config",
	)

	kubeletDir := "/var/lib/kubelet"
	if entries, err := os.ReadDir(kubeletDir); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".conf") || strings.HasSuffix(entry.Name(), ".kubeconfig") {
				paths = append(paths, filepath.Join(kubeletDir, entry.Name()))
			}
		}
	}

	return paths
}

func isKubeconfigData(data []byte) bool {
	s := string(data)
	if strings.Contains(s, "apiVersion") && strings.Contains(s, "clusters") && strings.Contains(s, "server") {
		return true
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil && strings.Contains(string(decoded), "apiVersion") {
		return true
	}

	return false
}

// BuildClientFromCluster creates a Kubernetes client from discovered cluster credentials.
func BuildClientFromCluster(cluster ClusterInfo) (kubernetes.Interface, error) {
	config := &rest.Config{
		Host:        cluster.Server,
		BearerToken: cluster.Token,
	}

	if len(cluster.CAData) > 0 {
		config.TLSClientConfig = rest.TLSClientConfig{
			CAData: cluster.CAData,
		}
	} else {
		config.TLSClientConfig = rest.TLSClientConfig{
			Insecure: true,
		}
	}

	return kubernetes.NewForConfig(config)
}
