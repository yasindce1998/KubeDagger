package honeypot_detect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type DetectResult struct {
	Checks  []CheckInfo `json:"checks"`
	IsHoneypot bool     `json:"is_honeypot"`
	Confidence float64  `json:"confidence"`
}

type CheckInfo struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	Suspicious bool   `json:"suspicious"`
}

func Execute(target, checks, output string) error {
	result := &DetectResult{}

	var checkList []struct {
		name   string
		detail string
		cmd    string
	}

	switch checks {
	case "kubelet":
		checkList = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"kubelet_version", "check kubelet version string for known honeypot patterns", "hp_kubelet_ver"},
			{"kubelet_timing", "measure API response times for synthetic delay detection", "hp_kubelet_time"},
			{"kubelet_caps", "query node capabilities for unrealistic resource claims", "hp_kubelet_caps"},
		}
	case "metrics":
		checkList = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"metric_entropy", "analyze metric time series for insufficient entropy (synthetic)", "hp_metric_entropy"},
			{"metric_patterns", "detect repetitive metric patterns indicating simulation", "hp_metric_patterns"},
			{"node_pressure", "check if node pressure signals are consistent with load", "hp_node_pressure"},
		}
	case "tokens":
		checkList = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"canary_tokens", "detect canary/honeytokens in mounted secrets and configmaps", "hp_canary_tokens"},
			{"token_validity", "test if SA tokens have unrealistically broad permissions", "hp_token_validity"},
			{"credential_traps", "identify credential files with suspicious access monitoring", "hp_cred_traps"},
		}
	default: // all
		checkList = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"kubelet_fingerprint", "fingerprint kubelet for honeypot indicators", "hp_kubelet_fp"},
			{"metric_analysis", "analyze cluster metrics for synthetic patterns", "hp_metrics"},
			{"token_inspection", "inspect tokens and secrets for canary indicators", "hp_tokens"},
			{"network_topology", "verify network topology consistency with claimed cluster size", "hp_network"},
			{"syscall_timing", "measure syscall latency for emulation detection", "hp_syscall_timing"},
			{"hardware_verify", "cross-reference /proc/cpuinfo with actual instruction timing", "hp_hardware"},
		}
	}

	suspiciousCount := 0
	for _, c := range checkList {
		cmd := c.cmd + "#" + checks
		status := sendCommand(target, cmd)
		suspicious := strings.Contains(status, "suspicious") || strings.Contains(status, "failed")
		if suspicious {
			suspiciousCount++
		}
		result.Checks = append(result.Checks, CheckInfo{
			Name:       c.name,
			Status:     status,
			Detail:     c.detail,
			Suspicious: suspicious,
		})
	}

	result.Confidence = float64(suspiciousCount) / float64(len(checkList))
	result.IsHoneypot = result.Confidence > 0.5

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func sendCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/honeypot_detect", nil)
	if err != nil {
		return "error: " + err.Error()
	}
	req.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "enabled"
	}
	return fmt.Sprintf("failed (HTTP %d)", resp.StatusCode)
}

func buildUserAgent(command string) string {
	userAgent := command
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "#"
	}
	return userAgent
}
