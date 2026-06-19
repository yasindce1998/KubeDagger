package autonomy

import "context"

type Engine struct {
	planner  *Planner
	executor *Executor
	state    *WorldState
}

func NewEngine(modExec ModuleExecutor) *Engine {
	rules := DefaultRules()
	planner := NewPlanner(rules)
	state := NewWorldState()
	executor := NewExecutor(planner, modExec, 20)

	return &Engine{
		planner:  planner,
		executor: executor,
		state:    state,
	}
}

func (e *Engine) Execute(ctx context.Context, obj Objective) (*Campaign, error) {
	return e.executor.Execute(ctx, obj, e.state)
}

func (e *Engine) Plan(obj Objective) *Plan {
	return e.planner.BuildPlan(obj, e.state)
}

func (e *Engine) State() *WorldState {
	return e.state
}

func (e *Engine) AddRule(rule Rule) {
	e.planner.rules = append(e.planner.rules, rule)
}
