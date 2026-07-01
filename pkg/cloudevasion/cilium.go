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

var ciliumNetworkPolicyGVR = schema.GroupVersionResource{
	Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies",
}

var ciliumEndpointGVR = schema.GroupVersionResource{
	Group: "cilium.io", Version: "v2", Resource: "ciliumendpoints",
}

func detectCilium(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kube-system", "cilium", "cilium-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=cilium",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cilium",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d cilium-agent pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=cilium-agent",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cilium",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d cilium-agent pods", len(pods.Items)),
			}}
		}
	}

	return nil
}

// EvadeCilium executes the specified Cilium network enforcement evasion technique.
func EvadeCilium(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "identity_spoof":
		return ciliumIdentitySpoof(ctx, client, dynClient)
	case "policy_gaps":
		return ciliumPolicyGaps(ctx, client, dynClient)
	case "hubble_blind":
		return ciliumHubbleBlind(ctx, client)
	case "endpoint_manipulate":
		return ciliumEndpointManipulate(ctx, dynClient)
	default:
		return ciliumIdentitySpoof(ctx, client, dynClient)
	}
}

func ciliumIdentitySpoof(ctx context.Context, _ kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Cilium Identity Spoofing:\n\n")

	sb.WriteString("  Cilium assigns security identities based on pod labels.\n")
	sb.WriteString("  Policies reference identities, not IPs — label manipulation = identity change.\n\n")

	endpoints, err := dynClient.Resource(ciliumEndpointGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list CiliumEndpoints: %v\n", err)
		sb.WriteString("  Cilium CRDs may not be installed\n")
		return &EvasionResult{Technique: "identity_spoof", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  CiliumEndpoints (%d):\n", len(endpoints.Items))
	identities := make(map[string]string)
	for _, ep := range endpoints.Items {
		if len(identities) >= 15 {
			break
		}
		status, _ := ep.Object["status"].(map[string]any)
		if identity, ok := status["identity"].(map[string]any); ok {
			id, _ := identity["id"].(float64)
			labels, _ := identity["labels"].([]any)
			key := fmt.Sprintf("%d", int(id))
			labelStr := fmt.Sprintf("%v", labels)
			identities[key] = labelStr
			fmt.Fprintf(&sb, "    Endpoint %s: identity=%s labels=%s\n", ep.GetName(), key, labelStr)
		}
	}

	sb.WriteString("\n  Identity spoofing techniques:\n")
	sb.WriteString("    1. Add labels matching a trusted identity's label set\n")
	sb.WriteString("    2. Cilium recalculates identity on label change — instant effect\n")
	sb.WriteString("    3. Target identities with broad egress/ingress allow rules\n")
	sb.WriteString("    4. System identities (kube-system) often have unrestricted access\n")
	sb.WriteString("    5. Reserved identities: health, init, unmanaged bypass most policies\n")

	return &EvasionResult{
		Technique: "identity_spoof",
		Success:   len(identities) > 0,
		Output:    sb.String(),
	}, nil
}

func ciliumPolicyGaps(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Cilium Network Policy Gaps:\n\n")

	policies, err := dynClient.Resource(ciliumNetworkPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list CiliumNetworkPolicies: %v\n", err)
		return &EvasionResult{Technique: "policy_gaps", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  CiliumNetworkPolicies (%d):\n", len(policies.Items))
	coveredNamespaces := make(map[string]bool)
	for _, policy := range policies.Items {
		ns := policy.GetNamespace()
		coveredNamespaces[ns] = true
		fmt.Fprintf(&sb, "    %s/%s\n", ns, policy.GetName())
	}

	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list namespaces: %v\n", err)
		return &EvasionResult{Technique: "policy_gaps", Success: false, Output: sb.String()}, nil
	}

	sb.WriteString("\n  Namespaces WITHOUT CiliumNetworkPolicy:\n")
	uncovered := 0
	for _, ns := range namespaces.Items {
		if ns.Name == "kube-system" || ns.Name == "kube-public" || ns.Name == "kube-node-lease" {
			continue
		}
		if !coveredNamespaces[ns.Name] {
			uncovered++
			fmt.Fprintf(&sb, "    [UNCOVERED] %s\n", ns.Name)
		}
	}

	k8sPolicies, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Fprintf(&sb, "\n  Standard K8s NetworkPolicies: %d\n", len(k8sPolicies.Items))
		sb.WriteString("  Note: Cilium enforces both CiliumNetworkPolicy AND standard NetworkPolicy\n")
	}

	sb.WriteString("\n  Exploitation:\n")
	sb.WriteString("    1. Deploy workloads in uncovered namespaces — no network restrictions\n")
	sb.WriteString("    2. Cilium default: allow-all when no policy selects a pod\n")
	sb.WriteString("    3. L7 policies may only cover HTTP — use raw TCP/UDP to bypass\n")
	sb.WriteString("    4. DNS-based policies: use IP directly to bypass FQDN rules\n")
	sb.WriteString("    5. Host-networking pods bypass Cilium datapath entirely\n")

	return &EvasionResult{
		Technique: "policy_gaps",
		Success:   uncovered > 0,
		Output:    sb.String(),
	}, nil
}

func ciliumHubbleBlind(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Cilium Hubble Observability Gaps:\n\n")

	sb.WriteString("  Hubble is Cilium's observability layer for network flow visibility.\n")
	sb.WriteString("  Gaps in Hubble deployment create monitoring blind spots.\n\n")

	namespaces := []string{"kube-system", "cilium", "cilium-system"}
	hubbleFound := false
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=hubble-relay",
		})
		if err == nil && len(pods.Items) > 0 {
			hubbleFound = true
			fmt.Fprintf(&sb, "  Hubble Relay: %s/%s (phase=%s)\n", ns, pods.Items[0].Name, pods.Items[0].Status.Phase)
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=hubble-ui",
		})
		if err == nil && len(pods.Items) > 0 {
			fmt.Fprintf(&sb, "  Hubble UI: %s/%s\n", ns, pods.Items[0].Name)
		}
	}

	if !hubbleFound {
		sb.WriteString("  [+] Hubble Relay NOT deployed — no centralized flow visibility\n")
		sb.WriteString("  Flows only visible locally on each node via cilium-agent\n\n")
	}

	configMaps, err := client.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			if strings.Contains(cm.Name, "cilium-config") {
				if monitorAgg, ok := cm.Data["monitor-aggregation"]; ok {
					fmt.Fprintf(&sb, "  Monitor aggregation: %s\n", monitorAgg)
					if monitorAgg == "medium" || monitorAgg == "maximum" {
						sb.WriteString("    [+] High aggregation — individual flows not logged\n")
					}
				}
				if hubbleEnabled, ok := cm.Data["enable-hubble"]; ok {
					fmt.Fprintf(&sb, "  Hubble enabled: %s\n", hubbleEnabled)
				}
			}
		}
	}

	sb.WriteString("\n  Blind spots to exploit:\n")
	sb.WriteString("    1. No Hubble Relay → no centralized flow export/alerting\n")
	sb.WriteString("    2. High monitor-aggregation → individual connections invisible\n")
	sb.WriteString("    3. Host-networking traffic bypasses Cilium datapath (and Hubble)\n")
	sb.WriteString("    4. Encrypted traffic (WireGuard mode) — Hubble sees headers only\n")
	sb.WriteString("    5. DNS flows may not be captured without Cilium DNS proxy enabled\n")
	sb.WriteString("    6. Short-lived connections during high aggregation window are dropped\n")

	return &EvasionResult{
		Technique: "hubble_blind",
		Success:   !hubbleFound,
		Output:    sb.String(),
	}, nil
}

func ciliumEndpointManipulate(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Cilium Endpoint Manipulation:\n\n")

	sb.WriteString("  CiliumEndpoint CRDs reflect endpoint state.\n")
	sb.WriteString("  Modifying labels changes the identity and policy enforcement.\n\n")

	endpoints, err := dynClient.Resource(ciliumEndpointGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list CiliumEndpoints: %v\n", err)
		return &EvasionResult{Technique: "endpoint_manipulate", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  CiliumEndpoints found: %d\n\n", len(endpoints.Items))
	shown := 0
	for _, ep := range endpoints.Items {
		if shown >= 10 {
			break
		}
		status, _ := ep.Object["status"].(map[string]any)
		networking, _ := status["networking"].(map[string]any)
		identity, _ := status["identity"].(map[string]any)

		fmt.Fprintf(&sb, "  Endpoint: %s/%s\n", ep.GetNamespace(), ep.GetName())
		if id, ok := identity["id"].(float64); ok {
			fmt.Fprintf(&sb, "    Identity: %d\n", int(id))
		}
		if addressing, ok := networking["addressing"].([]any); ok && len(addressing) > 0 {
			if addr, ok := addressing[0].(map[string]any); ok {
				fmt.Fprintf(&sb, "    IP: %v\n", addr["ipv4"])
			}
		}
		shown++
	}

	sb.WriteString("\n  Manipulation techniques:\n")
	sb.WriteString("    1. Modify pod labels → Cilium recalculates endpoint identity\n")
	sb.WriteString("    2. Add labels of privileged workload → inherit its policy permissions\n")
	sb.WriteString("    3. Remove all security-relevant labels → may get 'world' identity\n")
	sb.WriteString("    4. Match system endpoint labels for kube-system-level access\n")
	sb.WriteString("    5. Patch CiliumEndpoint status to confuse policy enforcement\n")

	return &EvasionResult{
		Technique: "endpoint_manipulate",
		Success:   len(endpoints.Items) > 0,
		Output:    sb.String(),
	}, nil
}
