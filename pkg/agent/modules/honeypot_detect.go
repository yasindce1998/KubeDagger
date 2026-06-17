package modules

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type HoneypotDetect struct{}

func (m *HoneypotDetect) Name() string        { return "honeypot_detect" }
func (m *HoneypotDetect) Platform() []string   { return []string{"linux", "windows", "darwin"} }

func (m *HoneypotDetect) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	var indicators []string
	score := 0

	if runtime.NumCPU() <= 1 {
		indicators = append(indicators, "single CPU (common in sandboxes)")
		score += 2
	}

	hostname, _ := os.Hostname()
	honeypotNames := []string{"honeypot", "sandbox", "malware", "analysis", "cuckoo", "vm-"}
	for _, name := range honeypotNames {
		if strings.Contains(strings.ToLower(hostname), name) {
			indicators = append(indicators, fmt.Sprintf("suspicious hostname: %s", hostname))
			score += 3
			break
		}
	}

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			cpuInfo := strings.ToLower(string(data))
			if strings.Contains(cpuInfo, "qemu") || strings.Contains(cpuInfo, "kvm") {
				indicators = append(indicators, "virtualized CPU (QEMU/KVM)")
				score++
			}
		}

		if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			product := strings.ToLower(strings.TrimSpace(string(data)))
			vmProducts := []string{"virtualbox", "vmware", "qemu", "bochs", "xen"}
			for _, vp := range vmProducts {
				if strings.Contains(product, vp) {
					indicators = append(indicators, fmt.Sprintf("VM product: %s", product))
					score++
					break
				}
			}
		}

		canaryFiles := []string{
			"/etc/canary",
			"/opt/dionaea",
			"/opt/cowrie",
			"/opt/kippo",
			"/opt/honeyd",
		}
		for _, f := range canaryFiles {
			if _, err := os.Stat(f); err == nil {
				indicators = append(indicators, fmt.Sprintf("honeypot artifact: %s", f))
				score += 5
			}
		}
	}

	envVars := []string{"ANALYSIS", "SANDBOX", "HONEYPOT"}
	for _, ev := range envVars {
		if os.Getenv(ev) != "" {
			indicators = append(indicators, fmt.Sprintf("suspicious env var: %s", ev))
			score += 3
		}
	}

	assessment := "LOW"
	if score >= 3 {
		assessment = "MEDIUM"
	}
	if score >= 5 {
		assessment = "HIGH"
	}

	output := fmt.Sprintf("Honeypot/Sandbox Risk: %s (score: %d)\n", assessment, score)
	if len(indicators) > 0 {
		output += "Indicators:\n- " + strings.Join(indicators, "\n- ")
	} else {
		output += "No indicators detected."
	}

	return &Result{
		Success: true,
		Output:  output,
	}, nil
}
