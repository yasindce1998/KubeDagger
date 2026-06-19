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
	"k8s.io/client-go/rest"
)

// Platform describes a detected CI/CD system and its running controllers.
type Platform struct {
	Name        string
	Detected    bool
	Namespace   string
	Controllers []string
}

// PoisonResult captures the outcome of a CI/CD supply-chain poisoning operation.
type PoisonResult struct {
	Platform string
	Action   string
	Target   string
	Success  bool
	Output   string
}

// DetectPlatforms discovers CI/CD systems running in the current cluster.
func DetectPlatforms(ctx context.Context) ([]Platform, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("not in cluster: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	var platforms []Platform

	tekton := detectTekton(ctx, client)
	if tekton.Detected {
		platforms = append(platforms, tekton)
	}

	argo := detectArgoCD(ctx, client)
	if argo.Detected {
		platforms = append(platforms, argo)
	}

	flux := detectFlux(ctx, client)
	if flux.Detected {
		platforms = append(platforms, flux)
	}

	return platforms, nil
}

func detectTekton(ctx context.Context, client kubernetes.Interface) Platform {
	p := Platform{Name: "tekton"}

	namespaces := []string{"tekton-pipelines", "openshift-pipelines"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/part-of=tekton-pipelines",
		})
		if err == nil && len(pods.Items) > 0 {
			p.Detected = true
			p.Namespace = ns
			for _, pod := range pods.Items {
				p.Controllers = append(p.Controllers, pod.Name)
			}
			break
		}
	}

	return p
}

func detectArgoCD(ctx context.Context, client kubernetes.Interface) Platform {
	p := Platform{Name: "argocd"}

	namespaces := []string{"argocd", "argo-cd"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/part-of=argocd",
		})
		if err == nil && len(pods.Items) > 0 {
			p.Detected = true
			p.Namespace = ns
			for _, pod := range pods.Items {
				p.Controllers = append(p.Controllers, pod.Name)
			}
			break
		}
	}

	return p
}

func detectFlux(ctx context.Context, client kubernetes.Interface) Platform {
	p := Platform{Name: "flux"}

	namespaces := []string{"flux-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=source-controller",
		})
		if err == nil && len(pods.Items) > 0 {
			p.Detected = true
			p.Namespace = ns
			for _, pod := range pods.Items {
				p.Controllers = append(p.Controllers, pod.Name)
			}
			break
		}
	}

	return p
}

// GetDynamicClient returns a dynamic Kubernetes client from the in-cluster config.
func GetDynamicClient() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(config)
}

// GetKubeClient returns a typed Kubernetes client from the in-cluster config.
func GetKubeClient() (kubernetes.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// ListCRDs lists custom resources matching the given GVR in the specified namespace.
func ListCRDs(ctx context.Context, dynClient dynamic.Interface, gvr schema.GroupVersionResource, ns string) ([]unstructured.Unstructured, error) {
	list, err := dynClient.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// FormatPlatforms returns a human-readable summary of detected CI/CD platforms.
func FormatPlatforms(platforms []Platform) string {
	if len(platforms) == 0 {
		return "no CI/CD platforms detected"
	}

	var sb strings.Builder
	for _, p := range platforms {
		fmt.Fprintf(&sb, "[%s] namespace=%s controllers=%d\n", p.Name, p.Namespace, len(p.Controllers))
		for _, c := range p.Controllers {
			fmt.Fprintf(&sb, "  - %s\n", c)
		}
	}
	return sb.String()
}
