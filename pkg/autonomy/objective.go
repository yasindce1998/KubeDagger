package autonomy

type ObjectiveType int

const (
	ObjectiveExfiltrate ObjectiveType = iota
	ObjectivePersist
	ObjectiveEscalate
	ObjectiveLateralMove
	ObjectiveEvade
	ObjectiveDiscover
)

func (o ObjectiveType) String() string {
	switch o {
	case ObjectiveExfiltrate:
		return "exfiltrate"
	case ObjectivePersist:
		return "persist"
	case ObjectiveEscalate:
		return "escalate"
	case ObjectiveLateralMove:
		return "lateral_move"
	case ObjectiveEvade:
		return "evade"
	case ObjectiveDiscover:
		return "discover"
	default:
		return "unknown"
	}
}

type Objective struct {
	Type     ObjectiveType
	Target   string
	Priority int
	Params   map[string]string
}
