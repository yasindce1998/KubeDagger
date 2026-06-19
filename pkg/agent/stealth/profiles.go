package stealth

type EndpointProfile struct {
	Checkin string
	Task    string
	Result  string
}

var Profiles = map[string]EndpointProfile{
	"legacy": {
		Checkin: "/checkin",
		Task:    "/task",
		Result:  "/result",
	},
	"telemetry": {
		Checkin: "/api/v2/telemetry/heartbeat",
		Task:    "/api/v2/telemetry/events",
		Result:  "/api/v2/telemetry/ingest",
	},
	"cdn": {
		Checkin: "/cdn/v1/assets/check",
		Task:    "/cdn/v1/assets/fetch",
		Result:  "/cdn/v1/assets/upload",
	},
	"webhook": {
		Checkin: "/hooks/github/push",
		Task:    "/hooks/github/status",
		Result:  "/hooks/github/release",
	},
}

func GetProfile(name string) EndpointProfile {
	if p, ok := Profiles[name]; ok {
		return p
	}
	return Profiles["telemetry"]
}

func DefaultProfile() EndpointProfile {
	return Profiles["telemetry"]
}
