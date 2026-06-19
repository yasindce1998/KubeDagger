package autonomy

import "sort"

type Planner struct {
	rules []Rule
}

func NewPlanner(rules []Rule) *Planner {
	return &Planner{rules: rules}
}

type Plan struct {
	Steps []Step
}

type Step struct {
	Rule       Rule
	Module     string
	ModuleArgs map[string]string
}

func (p *Planner) BuildPlan(objective Objective, state *WorldState) *Plan {
	applicable := p.findApplicable(objective.Type, state)
	if len(applicable) == 0 {
		return &Plan{}
	}

	sort.Slice(applicable, func(i, j int) bool {
		return applicable[i].Priority > applicable[j].Priority
	})

	var steps []Step
	simState := cloneState(state)

	for _, rule := range applicable {
		if !rule.Applicable(simState) {
			continue
		}
		steps = append(steps, Step{
			Rule:       rule,
			Module:     rule.Module,
			ModuleArgs: rule.ModuleArgs,
		})
		rule.ApplyEffects(simState)
	}

	return &Plan{Steps: steps}
}

func (p *Planner) FindNextAction(objective Objective, state *WorldState) *Step {
	applicable := p.findApplicable(objective.Type, state)
	if len(applicable) == 0 {
		return nil
	}

	sort.Slice(applicable, func(i, j int) bool {
		return applicable[i].Priority > applicable[j].Priority
	})

	for _, rule := range applicable {
		if rule.Applicable(state) {
			return &Step{
				Rule:       rule,
				Module:     rule.Module,
				ModuleArgs: rule.ModuleArgs,
			}
		}
	}
	return nil
}

func (p *Planner) findApplicable(objType ObjectiveType, state *WorldState) []Rule {
	var result []Rule
	for _, r := range p.rules {
		if r.Objective == objType {
			result = append(result, r)
		}
	}
	if len(result) == 0 {
		for _, r := range p.rules {
			if r.Applicable(state) {
				result = append(result, r)
			}
		}
	}
	return result
}

func cloneState(s *WorldState) *WorldState {
	ns := NewWorldState()
	for k, v := range s.AllFacts() {
		ns.SetFact(k, v)
	}
	return ns
}
