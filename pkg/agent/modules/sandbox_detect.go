/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package modules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SandboxDetect fingerprints the execution environment (gVisor, Kata,
// Firecracker, WSL, containers, VMs) and reports the operational impact of
// each detected isolation layer.
type SandboxDetect struct{}

func (m *SandboxDetect) Name() string       { return "sandbox_detect" }
func (m *SandboxDetect) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *SandboxDetect) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	if runtime.GOOS != "linux" {
		hostname, _ := os.Hostname()
		return &Result{
			Success: true,
			Output: fmt.Sprintf("sandbox detection not supported on this platform\n"+
				"runtime.GOOS: %s\nhostname: %s\n",
				runtime.GOOS, hostname),
		}, nil
	}

	root := args["root"]
	report := m.detectLinux(root)

	var sb strings.Builder
	sb.WriteString("Sandbox detection report:\n")
	if len(report.findings) == 0 {
		sb.WriteString("no sandbox, container, or VM indicators detected\n")
	} else {
		for _, f := range report.findings {
			fmt.Fprintf(&sb, "- %s: %s\n", f.name, f.implication)
		}
	}

	return &Result{
		Success: true,
		Output:  sb.String(),
	}, nil
}

type sandboxFinding struct {
	name        string
	implication string
}

type sandboxReport struct {
	findings []sandboxFinding
}

func (r *sandboxReport) add(name, implication string) {
	r.findings = append(r.findings, sandboxFinding{name: name, implication: implication})
}

func (m *SandboxDetect) detectLinux(root string) *sandboxReport {
	report := &sandboxReport{}

	procVersion := sandboxReadFile(filepath.Join(root, "/proc/version"))
	procVersionLower := strings.ToLower(procVersion)
	procMountsLower := strings.ToLower(sandboxReadFile(filepath.Join(root, "/proc/mounts")))

	// gVisor: user-space kernel sandbox (GKE Sandbox, runsc).
	if strings.Contains(procVersionLower, "gvisor") {
		report.add("gVisor detected",
			"syscall-level escapes and kernel exploit techniques will fail; eBPF loading unavailable")
	} else if strings.Contains(procMountsLower, "gvisor") {
		report.add("gVisor hint in /proc/mounts",
			"likely running under runsc; syscall interception differs from a real kernel")
	}

	// Kata Containers: lightweight micro-VMs backed by QEMU/Cloud Hypervisor.
	dmiID := filepath.Join(root, "/sys/devices/virtual/dmi/id")
	productName := sandboxReadFile(filepath.Join(dmiID, "product_name"))
	productVersion := sandboxReadFile(filepath.Join(dmiID, "product_version"))
	if strings.Contains(productName, "Kata") || strings.Contains(productVersion, "Kata") {
		report.add("Kata Containers detected",
			"isolated micro-VM: host kernel exploits and container escapes will not reach the node")
	}

	// Firecracker: microVM used by AWS Lambda / Fargate.
	if strings.Contains(productName, "Firecracker") {
		report.add("Firecracker microVM detected",
			"minimal VM device model (AWS Lambda/Fargate style); expect restricted syscall surface and no container host access")
	}

	// WSL.
	if strings.Contains(procVersionLower, "microsoft") {
		report.add("WSL detected",
			"Windows Subsystem for Linux: host integration via /mnt/c, defender telemetry may apply")
	}

	// Generic container indicators.
	if _, err := os.Stat(filepath.Join(root, "/.dockerenv")); err == nil {
		report.add("container detected (.dockerenv)",
			"running inside a container; breakout requires a container escape primitive")
	}
	cgroup1 := sandboxReadFile(filepath.Join(root, "/proc/1/cgroup"))
	for _, marker := range []string{"docker", "containerd", "kubepods"} {
		if strings.Contains(cgroup1, marker) {
			report.add(fmt.Sprintf("container detected (%s in /proc/1/cgroup)", marker),
				"orchestrated container environment; node credentials and host mounts are the escape targets")
			break
		}
	}

	// VM hints from DMI.
	sysVendor := sandboxReadFile(filepath.Join(dmiID, "sys_vendor"))
	vmVendors := map[string]string{
		"VMware":                "VMware VM: common in enterprise labs and analyst sandboxes",
		"QEMU":                  "QEMU/KVM VM: typical for cloud nodes and analysis sandboxes",
		"KVM":                   "KVM VM: typical for cloud nodes",
		"Xen":                   "Xen VM: common on legacy cloud instances (EC2 xen)",
		"Microsoft Corporation": "Hyper-V VM: Azure nodes and Windows hypervisors",
	}
	for vendor, implication := range vmVendors {
		if strings.Contains(sysVendor, vendor) {
			report.add(fmt.Sprintf("VM hint (DMI sys_vendor: %s)", vendor), implication)
			break
		}
	}

	return report
}

func sandboxReadFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
