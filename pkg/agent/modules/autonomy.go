package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/autonomy"
)

type Autonomy struct{}

func (m *Autonomy) Name() string      { return "autonomy" }
func (m *Autonomy) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *Autonomy) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "plan"
	}

	switch action {
	case "plan":
		return m.plan(args)
	case "status":
		return m.status()
	default:
		return nil, fmt.Errorf("unknown action: %s (valid: plan, status)", action)
	}
}

func (m *Autonomy) plan(args map[string]string) (*Result, error) {
	objType := args["objective"]
	if objType == "" {
		objType = "discover"
	}

	var ot autonomy.ObjectiveType
	switch objType {
	case "exfiltrate":
		ot = autonomy.ObjectiveExfiltrate
	case "persist":
		ot = autonomy.ObjectivePersist
	case "escalate":
		ot = autonomy.ObjectiveEscalate
	case "lateral_move":
		ot = autonomy.ObjectiveLateralMove
	case "evade":
		ot = autonomy.ObjectiveEvade
	case "discover":
		ot = autonomy.ObjectiveDiscover
	default:
		return nil, fmt.Errorf("unknown objective type: %s", objType)
	}

	obj := autonomy.Objective{
		Type:   ot,
		Target: args["target"],
		Params: args,
	}

	engine := autonomy.NewEngine(nil)
	plan := engine.Plan(obj)

	var lines []string
	lines = append(lines, fmt.Sprintf("objective: %s", objType))
	lines = append(lines, fmt.Sprintf("target: %s", args["target"]))
	lines = append(lines, fmt.Sprintf("planned_steps: %d", len(plan.Steps)))
	for i, step := range plan.Steps {
		lines = append(lines, fmt.Sprintf("  step_%d: %s (module: %s)", i+1, step.Rule.Name, step.Module))
	}

	return &Result{
		Success: true,
		Output:  strings.Join(lines, "\n"),
	}, nil
}

func (m *Autonomy) status() (*Result, error) {
	return &Result{
		Success: true,
		Output:  "autonomous objective engine ready\nobjectives: discover, exfiltrate, persist, escalate, lateral_move, evade\nplanner: forward-chaining rule engine\ndefault_rules: 7",
	}, nil
}
