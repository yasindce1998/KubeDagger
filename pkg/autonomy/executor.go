package autonomy

import (
	"context"
	"fmt"
	"maps"
	"strings"
)

type ModuleExecutor interface {
	ExecuteModule(ctx context.Context, name string, args map[string]string) (string, error)
}

type StepResult struct {
	Step    Step
	Output  string
	Success bool
	Error   string
}

type Campaign struct {
	Objective Objective
	Results   []StepResult
	State     *WorldState
	Complete  bool
}

type Executor struct {
	planner  *Planner
	modExec  ModuleExecutor
	maxSteps int
}

func NewExecutor(planner *Planner, modExec ModuleExecutor, maxSteps int) *Executor {
	if maxSteps <= 0 {
		maxSteps = 20
	}
	return &Executor{
		planner:  planner,
		modExec:  modExec,
		maxSteps: maxSteps,
	}
}

func (e *Executor) Execute(ctx context.Context, obj Objective, state *WorldState) (*Campaign, error) {
	campaign := &Campaign{
		Objective: obj,
		State:     state,
	}

	for i := range e.maxSteps {
		select {
		case <-ctx.Done():
			return campaign, ctx.Err()
		default:
		}

		step := e.planner.FindNextAction(obj, state)
		if step == nil {
			campaign.Complete = true
			break
		}

		args := make(map[string]string)
		maps.Copy(args, step.ModuleArgs)
		maps.Copy(args, obj.Params)

		output, err := e.modExec.ExecuteModule(ctx, step.Module, args)
		result := StepResult{
			Step:   *step,
			Output: output,
		}

		if err != nil {
			result.Success = false
			result.Error = err.Error()
		} else {
			result.Success = true
			step.Rule.ApplyEffects(state)
		}

		campaign.Results = append(campaign.Results, result)

		if !result.Success && i >= e.maxSteps/2 {
			break
		}
	}

	return campaign, nil
}

func (e *Executor) DryRun(obj Objective, state *WorldState) *Plan {
	return e.planner.BuildPlan(obj, state)
}

func FormatCampaign(c *Campaign) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Campaign: %s (target: %s)\n", c.Objective.Type, c.Objective.Target)
	fmt.Fprintf(&b, "Complete: %v\n", c.Complete)
	fmt.Fprintf(&b, "Steps executed: %d\n", len(c.Results))
	for i, r := range c.Results {
		status := "OK"
		if !r.Success {
			status = "FAIL: " + r.Error
		}
		fmt.Fprintf(&b, "  [%d] %s (%s) -> %s\n", i+1, r.Step.Rule.Name, r.Step.Module, status)
	}
	return b.String()
}
