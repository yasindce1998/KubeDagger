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

var cosignPolicyGVR = schema.GroupVersionResource{
	Group: "policy.sigstore.dev", Version: "v1beta1", Resource: "clusterimagepolicies",
}

func detectSigstore(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) []DetectionSystem {
	namespaces := []string{"cosign-system", "sigstore", "policy-controller-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=policy-controller",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "sigstore/cosign",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d policy-controller pods", len(pods.Items)),
			}}
		}
	}

	policies, err := dynClient.Resource(cosignPolicyGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(policies.Items) > 0 {
		return []DetectionSystem{{
			Name:     "sigstore/cosign",
			Detected: true,
			Details:  fmt.Sprintf("%d ClusterImagePolicy CRDs", len(policies.Items)),
		}}
	}

	webhooks, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(wh.Name, "policy.sigstore") || strings.Contains(wh.Name, "cosign") {
				return []DetectionSystem{{
					Name:     "sigstore/cosign",
					Detected: true,
					Details:  fmt.Sprintf("webhook: %s", wh.Name),
				}}
			}
		}
	}

	return nil
}

// EvadeSigstore executes the specified Sigstore/Cosign verification bypass technique.
func EvadeSigstore(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "policy_gaps":
		return sigstorePolicyGaps(ctx, client, dynClient)
	case "keyless_exploit":
		return sigstoreKeylessExploit(ctx, dynClient)
	case "webhook_failure":
		return sigstoreWebhookFailure(ctx, client)
	case "transparency_forge":
		return sigstoreTransparencyForge(ctx, client, dynClient)
	default:
		return sigstorePolicyGaps(ctx, client, dynClient)
	}
}

func sigstorePolicyGaps(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Sigstore/Cosign Policy Gap Analysis:\n\n")

	policies, err := dynClient.Resource(cosignPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterImagePolicies: %v\n", err)
		sb.WriteString("  Sigstore CRDs may not be installed\n")
		return &EvasionResult{Technique: "policy_gaps", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  ClusterImagePolicies (%d):\n\n", len(policies.Items))

	coveredRegistries := make(map[string]bool)
	for _, policy := range policies.Items {
		name := policy.GetName()
		spec, _ := policy.Object["spec"].(map[string]any)

		fmt.Fprintf(&sb, "  Policy: %s\n", name)
		if images, ok := spec["images"].([]any); ok {
			for _, img := range images {
				if imgMap, ok := img.(map[string]any); ok {
					if glob, ok := imgMap["glob"].(string); ok {
						fmt.Fprintf(&sb, "    Image glob: %s\n", glob)
						coveredRegistries[glob] = true
					}
				}
			}
		}

		if mode, ok := spec["mode"].(string); ok {
			fmt.Fprintf(&sb, "    Mode: %s\n", mode)
			if mode == "warn" {
				sb.WriteString("    [WEAK] Mode=warn — violations logged but not blocked\n")
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("  Covered image patterns:\n")
	for pattern := range coveredRegistries {
		fmt.Fprintf(&sb, "    %s\n", pattern)
	}

	sb.WriteString("\n  Potential gaps:\n")
	sb.WriteString("    - Images from registries not matching any glob are UNSIGNED OK\n")
	sb.WriteString("    - Use a registry not covered by policy globs\n")
	sb.WriteString("    - Init containers and ephemeral containers may not be validated\n")
	sb.WriteString("    - Sidecar containers injected by mutating webhooks bypass validation\n")

	pods, _ := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 20})
	if pods != nil {
		sb.WriteString("\n  Sample registries in use:\n")
		registries := make(map[string]bool)
		for _, pod := range pods.Items {
			for _, c := range pod.Spec.Containers {
				parts := strings.SplitN(c.Image, "/", 2)
				if len(parts) > 1 && strings.Contains(parts[0], ".") {
					registries[parts[0]] = true
				}
			}
		}
		for reg := range registries {
			covered := false
			for pattern := range coveredRegistries {
				if strings.Contains(pattern, reg) {
					covered = true
				}
			}
			if !covered {
				fmt.Fprintf(&sb, "    [UNCOVERED] %s\n", reg)
			} else {
				fmt.Fprintf(&sb, "    [OK] %s\n", reg)
			}
		}
	}

	return &EvasionResult{
		Technique: "policy_gaps",
		Success:   len(policies.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func sigstoreKeylessExploit(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Sigstore Keyless Signing Exploit:\n\n")

	sb.WriteString("  Keyless signing uses OIDC identity (email/CI subject) as signer.\n")
	sb.WriteString("  Policies validate issuer+subject — weak constraints allow forgery.\n\n")

	policies, err := dynClient.Resource(cosignPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list policies: %v\n", err)
		return &EvasionResult{Technique: "keyless_exploit", Success: false, Output: sb.String()}, nil
	}

	weakPolicies := 0
	for _, policy := range policies.Items {
		spec, _ := policy.Object["spec"].(map[string]any)
		authorities, _ := spec["authorities"].([]any)

		for _, auth := range authorities {
			authMap, _ := auth.(map[string]any)
			if keyless, ok := authMap["keyless"].(map[string]any); ok {
				fmt.Fprintf(&sb, "  Policy %s — keyless authority:\n", policy.GetName())

				if identities, ok := keyless["identities"].([]any); ok {
					for _, id := range identities {
						idMap, _ := id.(map[string]any)
						issuer, _ := idMap["issuer"].(string)
						subject, _ := idMap["subject"].(string)
						issuerRegExp, _ := idMap["issuerRegExp"].(string)
						subjectRegExp, _ := idMap["subjectRegExp"].(string)

						fmt.Fprintf(&sb, "    Issuer: %s (regex: %s)\n", issuer, issuerRegExp)
						fmt.Fprintf(&sb, "    Subject: %s (regex: %s)\n", subject, subjectRegExp)

						if issuer == "" && issuerRegExp == "" {
							sb.WriteString("    [CRITICAL] No issuer constraint — ANY OIDC provider accepted\n")
							weakPolicies++
						}
						if subject == "" && subjectRegExp == "" {
							sb.WriteString("    [CRITICAL] No subject constraint — ANY identity accepted\n")
							weakPolicies++
						}
						if subjectRegExp != "" && !strings.Contains(subjectRegExp, "^") {
							sb.WriteString("    [WEAK] Subject regex without anchor — partial match possible\n")
							weakPolicies++
						}
					}
				} else {
					sb.WriteString("    [CRITICAL] No identities specified — any keyless signer accepted\n")
					weakPolicies++
				}
			}
		}
	}

	sb.WriteString("\n  Keyless bypass strategies:\n")
	sb.WriteString("    1. Sign with any OIDC identity matching weak issuer/subject regex\n")
	sb.WriteString("    2. Use GitHub Actions OIDC from any public repo if issuer is github\n")
	sb.WriteString("    3. Self-hosted OIDC provider matching expected issuer URL pattern\n")
	sb.WriteString("    4. Email-based signing with attacker-controlled domain\n")
	sb.WriteString("    5. Expired certificates still valid if policy doesn't check Rekor timestamp\n")

	return &EvasionResult{
		Technique: "keyless_exploit",
		Success:   weakPolicies > 0,
		Output:    sb.String(),
	}, nil
}

func sigstoreWebhookFailure(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Sigstore Webhook Failure Mode:\n\n")

	webhooks, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list webhooks: %v\n", err)
		return &EvasionResult{Technique: "webhook_failure", Success: false, Output: sb.String()}, nil
	}

	found := false
	failOpen := false
	for _, wh := range webhooks.Items {
		if !strings.Contains(wh.Name, "sigstore") && !strings.Contains(wh.Name, "cosign") && !strings.Contains(wh.Name, "policy-controller") {
			continue
		}
		found = true
		fmt.Fprintf(&sb, "  Webhook: %s\n", wh.Name)

		for _, webhook := range wh.Webhooks {
			fmt.Fprintf(&sb, "    Hook: %s\n", webhook.Name)
			if webhook.FailurePolicy != nil {
				fmt.Fprintf(&sb, "    FailurePolicy: %s\n", *webhook.FailurePolicy)
				if string(*webhook.FailurePolicy) == "Ignore" {
					failOpen = true
					sb.WriteString("    [CRITICAL] Fail-open — killing policy-controller bypasses ALL verification!\n")
				}
			}
			if webhook.TimeoutSeconds != nil {
				fmt.Fprintf(&sb, "    Timeout: %ds\n", *webhook.TimeoutSeconds)
			}
			if webhook.NamespaceSelector != nil {
				fmt.Fprintf(&sb, "    NamespaceSelector: %v\n", webhook.NamespaceSelector.MatchLabels)
				for _, expr := range webhook.NamespaceSelector.MatchExpressions {
					fmt.Fprintf(&sb, "      %s %s %v\n", expr.Key, expr.Operator, expr.Values)
				}
			}
		}
	}

	if !found {
		sb.WriteString("  No Sigstore/policy-controller webhooks found\n")
	}

	sb.WriteString("\n  Webhook bypass strategies:\n")
	sb.WriteString("    1. If FailurePolicy=Ignore: kill policy-controller → all images allowed\n")
	sb.WriteString("    2. Deploy in excluded namespace (check namespaceSelector)\n")
	sb.WriteString("    3. Flood API server to trigger webhook timeout\n")
	sb.WriteString("    4. Delete the ValidatingWebhookConfiguration directly\n")
	sb.WriteString("    5. Scale policy-controller to 0 during deployment window\n")

	return &EvasionResult{
		Technique: "webhook_failure",
		Success:   failOpen,
		Output:    sb.String(),
	}, nil
}

func sigstoreTransparencyForge(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Sigstore Transparency Log Analysis:\n\n")

	sb.WriteString("  Rekor is Sigstore's transparency log — records all signing events.\n")
	sb.WriteString("  Policies may or may not require Rekor inclusion proof.\n\n")

	policies, err := dynClient.Resource(cosignPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list policies: %v\n", err)
		return &EvasionResult{Technique: "transparency_forge", Success: false, Output: sb.String()}, nil
	}

	noTlogRequired := 0
	for _, policy := range policies.Items {
		spec, _ := policy.Object["spec"].(map[string]any)
		authorities, _ := spec["authorities"].([]any)

		for _, auth := range authorities {
			authMap, _ := auth.(map[string]any)

			noTlog := false
			if ctlog, ok := authMap["ctlog"].(map[string]any); ok {
				if url, _ := ctlog["url"].(string); url == "" {
					noTlog = true
				}
			} else {
				noTlog = true
			}

			if noTlog {
				noTlogRequired++
				fmt.Fprintf(&sb, "  Policy %s: no transparency log verification required\n", policy.GetName())
			}
		}
	}

	configMaps, err := client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "sigstore") || strings.Contains(cm.Name, "cosign") {
				fmt.Fprintf(&sb, "  ConfigMap: %s/%s\n", cm.Namespace, cm.Name)
				for key := range cm.Data {
					fmt.Fprintf(&sb, "    Key: %s\n", key)
				}
			}
		}
	}

	sb.WriteString("\n  Transparency log weaknesses:\n")
	sb.WriteString("    1. No tlog requirement → signatures valid without Rekor proof\n")
	sb.WriteString("    2. Private Sigstore deployment may use custom Rekor (controllable)\n")
	sb.WriteString("    3. Offline signing (--tlog-upload=false) creates valid but unlogged sigs\n")
	sb.WriteString("    4. Rekor sharding — old entries in archived shards may not be checked\n")
	sb.WriteString("    5. If custom TUF root is used: compromise TUF to accept any Rekor\n")

	return &EvasionResult{
		Technique: "transparency_forge",
		Success:   noTlogRequired > 0,
		Output:    sb.String(),
	}, nil
}
