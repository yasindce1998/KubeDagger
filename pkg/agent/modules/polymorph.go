package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/polymorph"
)

type Polymorph struct{}

func (m *Polymorph) Name() string      { return "polymorph" }
func (m *Polymorph) Platform() []string { return []string{"linux"} }

func (m *Polymorph) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "mutate"
	}

	switch action {
	case "mutate":
		return m.mutate(args)
	case "status":
		return m.status()
	default:
		return nil, fmt.Errorf("unknown action: %s (valid: mutate, status)", action)
	}
}

func (m *Polymorph) mutate(args map[string]string) (*Result, error) {
	prog := &polymorph.Program{
		Name:    "kubedagger_probe",
		License: "GPL",
		Instructions: []polymorph.Instruction{
			polymorph.MovImm(polymorph.BPFRegR6, 0),
			polymorph.MovImm(polymorph.BPFRegR7, 42),
			polymorph.AddImm(polymorph.BPFRegR6, 1),
			polymorph.MovReg(polymorph.BPFRegR0, polymorph.BPFRegR6),
			polymorph.Exit(),
		},
	}

	engine := polymorph.NewEngine(0)

	transforms := args["transforms"]
	if transforms != "" {
		var selected []polymorph.Transform
		for _, name := range strings.Split(transforms, ",") {
			switch strings.TrimSpace(name) {
			case "nop":
				selected = append(selected, &polymorph.NOPInsertion{})
			case "register":
				selected = append(selected, &polymorph.RegisterRename{})
			case "constant":
				selected = append(selected, &polymorph.ConstantObfuscation{})
			case "deadcode":
				selected = append(selected, &polymorph.DeadCodeInsertion{})
			case "reorder":
				selected = append(selected, &polymorph.InstructionReorder{})
			}
		}
		if len(selected) > 0 {
			engine.SetTransforms(selected)
		}
	}

	mutated, err := engine.Mutate(prog)
	if err != nil {
		return nil, fmt.Errorf("mutation failed: %w", err)
	}

	var summary []string
	summary = append(summary, fmt.Sprintf("original_instructions: %d", len(prog.Instructions)))
	summary = append(summary, fmt.Sprintf("mutated_instructions: %d", len(mutated.Instructions)))

	history := engine.History()
	if len(history) > 0 {
		last := history[len(history)-1]
		summary = append(summary, fmt.Sprintf("seed: %016x", last.Seed))
		summary = append(summary, fmt.Sprintf("hash: %x", last.Hash[:8]))
		summary = append(summary, fmt.Sprintf("transforms_applied: %s", strings.Join(last.Transforms, ", ")))
	}

	encoded := polymorph.EncodeInstructions(mutated.Instructions)
	summary = append(summary, fmt.Sprintf("bytecode_size: %d bytes", len(encoded)))

	return &Result{
		Success: true,
		Output:  strings.Join(summary, "\n"),
	}, nil
}

func (m *Polymorph) status() (*Result, error) {
	return &Result{
		Success: true,
		Output:  "polymorphism engine ready\ntransforms: nop_insertion, register_rename, constant_obfuscation, dead_code_insertion, instruction_reorder",
	}, nil
}
