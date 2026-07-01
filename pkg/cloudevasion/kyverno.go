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

var kyvernoClusterPolicyGVR = schema.GroupVersionResource{
	Group: "kyverno.io", Version: "v1", Resource: "clusterpolicies",
}

var kyvernoPolicyGVR = schema.GroupVersionResource{
	Group: "kyverno.io", Version: "v1", Resource: "policies",
}

// EvadeKyverno executes the specified Kyverno policy engine evasion technique.
func EvadeKyverno(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "policy_gaps":
		return kyvernoPolicyGaps(ctx, client, dynClient)
	case "background_bypass":
		return kyvernoBackgroundBypass(ctx, dynClient)
	case "webhook_race":
		return kyvernoWebhookRace(ctx, client)
	case "mutate_exploit":
		return kyvernoMutateExploit(ctx, dynClient)
	default:
		return kyvernoPolicyGaps(ctx, client, dynClient)
	}
}

func kyvernoPolicyGaps(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kyverno Policy Gap Analysis:\n\n")

	clusterPolicies, err := dynClient.Resource(kyvernoClusterPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterPolicies: %v\n", err)
		return &EvasionResult{Technique: "policy_gaps", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  ClusterPolicies (%d):\n", len(clusterPolicies.Items))

	coveredKinds := make(map[string]bool)
	for _, policy := range clusterPolicies.Items {
		name := policy.GetName()
		spec, _ := policy.Object["spec"].(map[string]any)

		fmt.Fprintf(&sb, "    %s", name)
		if validationFailure, ok := spec["validationFailureAction"].(string); ok {
			fmt.Fprintf(&sb, " (action=%s)", validationFailure)
		}
		sb.WriteString("\n")

		if rules, ok := spec["rules"].([]any); ok {
			for _, rule := range rules {
				ruleMap, _ := rule.(map[string]any)
				if match, ok := ruleMap["match"].(map[string]any); ok {
					if resources, ok := match["resources"].(map[string]any); ok {
						if kinds, ok := resources["kinds"].([]any); ok {
							for _, k := range kinds {
								if ks, ok := k.(string); ok {
									coveredKinds[ks] = true
								}
							}
						}
					}
				}
			}
		}
	}

	policies, err := dynClient.Resource(kyvernoPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Fprintf(&sb, "\n  Namespace Policies (%d):\n", len(policies.Items))
		for _, policy := range policies.Items {
			fmt.Fprintf(&sb, "    %s/%s\n", policy.GetNamespace(), policy.GetName())
		}
	}

	sb.WriteString("\n  Resource kinds covered by policies:\n")
	for kind := range coveredKinds {
		fmt.Fprintf(&sb, "    - %s\n", kind)
	}

	sb.WriteString("\n  Potential gaps (uncovered kinds):\n")
	commonKinds := []string{"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Service", "Ingress", "ConfigMap", "Secret", "ServiceAccount", "Role", "ClusterRole", "RoleBinding", "NetworkPolicy"}
	gaps := 0
	for _, kind := range commonKinds {
		if !coveredKinds[kind] {
			fmt.Fprintf(&sb, "    [GAP] %s — no validation policy\n", kind)
			gaps++
		}
	}

	if gaps == 0 {
		sb.WriteString("    All common resource kinds have policies\n")
		sb.WriteString("    Check for namespace-scoped exclusions instead\n")
	}

	namespaces, _ := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if namespaces != nil {
		sb.WriteString("\n  Namespace exclusion check:\n")
		for _, ns := range namespaces.Items {
			for k, v := range ns.Labels {
				if strings.Contains(k, "kyverno") || strings.Contains(k, "policy") || strings.Contains(v, "exclude") {
					fmt.Fprintf(&sb, "    %s: %s=%s\n", ns.Name, k, v)
				}
			}
		}
	}

	return &EvasionResult{
		Technique: "policy_gaps",
		Success:   gaps > 0 || len(clusterPolicies.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func kyvernoBackgroundBypass(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kyverno Background Scan Bypass:\n\n")

	sb.WriteString("  Policies with background=false only validate NEW requests.\n")
	sb.WriteString("  Existing resources that violate policy are never flagged.\n\n")

	clusterPolicies, err := dynClient.Resource(kyvernoClusterPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterPolicies: %v\n", err)
		return &EvasionResult{Technique: "background_bypass", Success: false, Output: sb.String()}, nil
	}

	backgroundDisabled := 0
	auditMode := 0
	for _, policy := range clusterPolicies.Items {
		spec, _ := policy.Object["spec"].(map[string]any)
		name := policy.GetName()

		background, _ := spec["background"].(bool)
		validationAction, _ := spec["validationFailureAction"].(string)

		if !background {
			backgroundDisabled++
			fmt.Fprintf(&sb, "  [BYPASS] %s — background=false\n", name)
			fmt.Fprintf(&sb, "    Pre-existing violations are INVISIBLE\n")
		}

		if strings.ToLower(validationAction) == "audit" {
			auditMode++
			fmt.Fprintf(&sb, "  [WEAK] %s — validationFailureAction=Audit (not enforced)\n", name)
		}
	}

	fmt.Fprintf(&sb, "\n  Summary:\n")
	fmt.Fprintf(&sb, "    Policies with background=false: %d\n", backgroundDisabled)
	fmt.Fprintf(&sb, "    Policies in Audit mode (not blocking): %d\n", auditMode)

	sb.WriteString("\n  Exploitation:\n")
	sb.WriteString("    1. Directly modify existing resources (bypasses background=false)\n")
	sb.WriteString("    2. Use kubectl edit/patch instead of delete+create\n")
	sb.WriteString("    3. Modify resources during Kyverno controller restart window\n")
	sb.WriteString("    4. Audit-mode policies only log — deploy anything and check later\n")
	sb.WriteString("    5. Use subresources (status, scale) which bypass validation\n")

	return &EvasionResult{
		Technique: "background_bypass",
		Success:   backgroundDisabled > 0 || auditMode > 0,
		Output:    sb.String(),
	}, nil
}

func kyvernoWebhookRace(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kyverno Webhook Race Condition:\n\n")

	webhooks, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ValidatingWebhookConfigurations: %v\n", err)
		return &EvasionResult{Technique: "webhook_race", Success: false, Output: sb.String()}, nil
	}

	found := false
	for _, wh := range webhooks.Items {
		if !strings.Contains(wh.Name, "kyverno") {
			continue
		}
		found = true
		fmt.Fprintf(&sb, "  Webhook: %s\n", wh.Name)
		for _, webhook := range wh.Webhooks {
			fmt.Fprintf(&sb, "    Rule: %s\n", webhook.Name)
			if webhook.FailurePolicy != nil {
				fmt.Fprintf(&sb, "    FailurePolicy: %s\n", *webhook.FailurePolicy)
				if string(*webhook.FailurePolicy) == "Ignore" {
					sb.WriteString("    [CRITICAL] FailurePolicy=Ignore — bypass by killing Kyverno!\n")
				}
			}
			if webhook.TimeoutSeconds != nil {
				fmt.Fprintf(&sb, "    Timeout: %ds\n", *webhook.TimeoutSeconds)
			}
			if webhook.NamespaceSelector != nil {
				fmt.Fprintf(&sb, "    NamespaceSelector: %v\n", webhook.NamespaceSelector.MatchLabels)
			}
		}
		sb.WriteString("\n")
	}

	mutatingWebhooks, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range mutatingWebhooks.Items {
			if strings.Contains(wh.Name, "kyverno") {
				fmt.Fprintf(&sb, "  MutatingWebhook: %s\n", wh.Name)
				for _, webhook := range wh.Webhooks {
					if webhook.FailurePolicy != nil {
						fmt.Fprintf(&sb, "    FailurePolicy: %s\n", *webhook.FailurePolicy)
					}
				}
			}
		}
	}

	if !found {
		sb.WriteString("  No Kyverno webhooks found\n")
	}

	sb.WriteString("\n  Race/bypass strategies:\n")
	sb.WriteString("    1. If FailurePolicy=Ignore: crash Kyverno pods → all requests pass\n")
	sb.WriteString("    2. Exhaust webhook timeout (flood API server with requests)\n")
	sb.WriteString("    3. Deploy resource during Kyverno rolling update window\n")
	sb.WriteString("    4. Use namespaces excluded by namespaceSelector\n")
	sb.WriteString("    5. Scale Kyverno to 0 replicas, deploy, then restore\n")
	sb.WriteString("    6. Delete the ValidatingWebhookConfiguration directly\n")

	return &EvasionResult{
		Technique: "webhook_race",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func kyvernoMutateExploit(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Kyverno Mutate Rule Exploitation:\n\n")

	sb.WriteString("  Kyverno mutate rules modify resources on admission.\n")
	sb.WriteString("  If we can influence mutate inputs, we control the mutation output.\n\n")

	clusterPolicies, err := dynClient.Resource(kyvernoClusterPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterPolicies: %v\n", err)
		return &EvasionResult{Technique: "mutate_exploit", Success: false, Output: sb.String()}, nil
	}

	mutateRules := 0
	for _, policy := range clusterPolicies.Items {
		spec, _ := policy.Object["spec"].(map[string]any)
		rules, _ := spec["rules"].([]any)

		for _, rule := range rules {
			ruleMap, _ := rule.(map[string]any)
			if _, hasMutate := ruleMap["mutate"]; hasMutate {
				mutateRules++
				ruleName, _ := ruleMap["name"].(string)
				fmt.Fprintf(&sb, "  Mutate rule: %s/%s\n", policy.GetName(), ruleName)

				mutate, _ := ruleMap["mutate"].(map[string]any)
				if patchStrategic, ok := mutate["patchStrategicMerge"].(map[string]any); ok {
					fmt.Fprintf(&sb, "    Type: patchStrategicMerge\n")
					fmt.Fprintf(&sb, "    Patch: %v\n", patchStrategic)
				}
				if patchesJSON, ok := mutate["patchesJson6902"].(string); ok {
					fmt.Fprintf(&sb, "    Type: patchesJson6902\n")
					preview := patchesJSON
					if len(preview) > 100 {
						preview = preview[:100] + "..."
					}
					fmt.Fprintf(&sb, "    Patch: %s\n", preview)
				}
				sb.WriteString("\n")
			}
		}
	}

	if mutateRules == 0 {
		sb.WriteString("  No mutate rules found\n")
	}

	sb.WriteString("\n  Mutation exploitation vectors:\n")
	sb.WriteString("    1. Mutate rules adding labels → leverage for RBAC/NetworkPolicy matching\n")
	sb.WriteString("    2. Mutate rules injecting sidecars → our containers get the sidecar too\n")
	sb.WriteString("    3. Mutate rules setting defaults → override with higher-priority fields\n")
	sb.WriteString("    4. Mutate rules using context variables → inject via configmap/apiCall\n")
	sb.WriteString("    5. Generate rules → trigger to create resources we control\n")

	return &EvasionResult{
		Technique: "mutate_exploit",
		Success:   mutateRules > 0,
		Output:    sb.String(),
	}, nil
}
