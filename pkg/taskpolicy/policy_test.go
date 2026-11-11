package taskpolicy

import (
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
)

func TestCheck(t *testing.T) {
	for _, tt := range []struct {
		name, agent, taskType, namespace string
		wantErr                          bool
	}{
		{name: "allowed", agent: "a1", taskType: "module", namespace: "lab"},
		{name: "outside scope", agent: "a1", taskType: "module", namespace: "prod", wantErr: true},
		{name: "blank agent", agent: "  ", taskType: "module", namespace: "lab", wantErr: true},
		{name: "blank type", agent: "a1", taskType: "  ", namespace: "lab", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, err := events.NewStore("")
			if err != nil {
				t.Fatal(err)
			}
			p := Policy{Scope: &scope.Scope{Namespaces: []string{"lab"}}, Events: store}
			payload := map[string]string{"namespace": tt.namespace, "token": "sensitive"}
			if err := p.Check(tt.agent, tt.taskType, payload); (err != nil) != tt.wantErr {
				t.Fatalf("Check() = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				evs := store.List(0, 0)
				if len(evs) != 1 || evs[0].Type != events.TypeTaskRejected || evs[0].Payload != nil {
					t.Fatalf("unexpected rejection audit: %+v", evs)
				}
			} else if store.Count() != 0 {
				t.Error("validation alone must not record successful submission")
			}
		})
	}
}

func TestPolicyWithoutIntegrations(t *testing.T) {
	p := Policy{}
	if err := p.Check("a1", "module", nil); err != nil {
		t.Fatal(err)
	}
	p.RecordSubmitted("a1", "module", nil)
}

func TestSubmissionSnapshot(t *testing.T) {
	store, err := events.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]string{"name": "example"}
	Policy{Events: store}.RecordSubmitted("a1", "module", payload)
	payload["name"] = "changed"
	if got := store.List(0, 1)[0].Payload["name"]; got != "example" {
		t.Fatalf("audit payload changed after submission: %q", got)
	}
}

func TestRejectionAuditDoesNotLeakURLCredentials(t *testing.T) {
	store, err := events.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Scope: &scope.Scope{Domains: []string{"allowed.example"}}, Events: store}
	err = p.Check("a1", "module", map[string]string{"url": "https://user:secret@outside.example/?token=sensitive"})
	if err == nil {
		t.Fatal("expected out-of-scope URL to be rejected")
	}
	ev := store.List(0, 1)[0]
	if strings.Contains(ev.Detail, "secret") || strings.Contains(ev.Detail, "sensitive") || ev.Payload != nil {
		t.Fatalf("rejection audit leaked target credentials: %+v", ev)
	}
}
