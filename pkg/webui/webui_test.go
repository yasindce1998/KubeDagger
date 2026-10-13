package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/yasindce1998/KubeDagger/pkg/events"
)

func newTestServer(token string) *Server {
	return NewServer(":0", token)
}

func TestNewServerNoAuth(t *testing.T) {
	s := newTestServer("")
	if s.auth.Enabled {
		t.Error("auth should be disabled with empty token")
	}
}

func TestNewServerWithAuth(t *testing.T) {
	s := newTestServer("secret")
	if !s.auth.Enabled {
		t.Error("auth should be enabled with non-empty token")
	}
	if s.auth.Token != "secret" {
		t.Errorf("token = %q, want %q", s.auth.Token, "secret")
	}
}

func TestHandleAgentRegister(t *testing.T) {
	s := newTestServer("")

	body := `{"id":"agent-1","hostname":"node-1","ip":"10.0.0.1","os":"linux","arch":"amd64"}`
	req := httptest.NewRequest(http.MethodPost, "/api/agents/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleAgentRegister(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "registered" {
		t.Errorf("status = %q, want %q", resp["status"], "registered")
	}

	s.agents.mu.RLock()
	_, ok := s.agents.agents["agent-1"]
	s.agents.mu.RUnlock()
	if !ok {
		t.Error("agent not stored after registration")
	}
}

func TestHandleAgentRegisterMethodNotAllowed(t *testing.T) {
	s := newTestServer("")
	req := httptest.NewRequest(http.MethodGet, "/api/agents/register", nil)
	w := httptest.NewRecorder()

	s.handleAgentRegister(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleAgents(t *testing.T) {
	s := newTestServer("")
	s.agents.mu.Lock()
	s.agents.agents["a1"] = &AgentInfo{ID: "a1", Hostname: "node1"}
	s.agents.agents["a2"] = &AgentInfo{ID: "a2", Hostname: "node2"}
	s.agents.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	w := httptest.NewRecorder()

	s.handleAgents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var agents []AgentInfo
	if err := json.NewDecoder(w.Body).Decode(&agents); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(agents))
	}
}

func TestHandleNewCommand(t *testing.T) {
	s := newTestServer("")

	body := `{"agent_id":"agent-1","module":"recon","args":{"target":"default"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/commands/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleNewCommand(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var cmd Command
	if err := json.NewDecoder(w.Body).Decode(&cmd); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cmd.Status != "pending" {
		t.Errorf("status = %q, want %q", cmd.Status, "pending")
	}
	if cmd.AgentID != "agent-1" {
		t.Errorf("agent_id = %q, want %q", cmd.AgentID, "agent-1")
	}
	if !strings.HasPrefix(cmd.ID, "cmd-") {
		t.Errorf("id %q doesn't have cmd- prefix", cmd.ID)
	}
}

func TestHandlePollCommands(t *testing.T) {
	s := newTestServer("")

	s.agents.mu.Lock()
	s.agents.agents["agent-1"] = &AgentInfo{ID: "agent-1"}
	s.agents.mu.Unlock()

	s.commands.mu.Lock()
	cmd := &Command{ID: "cmd-1", AgentID: "agent-1", Module: "scan", Status: "pending"}
	s.commands.commands["cmd-1"] = cmd
	s.commands.pending["agent-1"] = []*Command{cmd}
	s.commands.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/commands/poll?agent_id=agent-1", nil)
	w := httptest.NewRecorder()

	s.handlePollCommands(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var cmds []*Command
	if err := json.NewDecoder(w.Body).Decode(&cmds); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cmds) != 1 {
		t.Fatalf("expected 1 command, got %d", len(cmds))
	}
	if cmds[0].Status != "dispatched" {
		t.Errorf("status = %q, want %q", cmds[0].Status, "dispatched")
	}

	// Second poll should return empty
	req2 := httptest.NewRequest(http.MethodGet, "/api/commands/poll?agent_id=agent-1", nil)
	w2 := httptest.NewRecorder()
	s.handlePollCommands(w2, req2)

	var cmds2 []*Command
	_ = json.NewDecoder(w2.Body).Decode(&cmds2)
	if len(cmds2) != 0 {
		t.Errorf("second poll should return 0 commands, got %d", len(cmds2))
	}
}

func TestHandlePollCommandsMissingAgentID(t *testing.T) {
	s := newTestServer("")
	req := httptest.NewRequest(http.MethodGet, "/api/commands/poll", nil)
	w := httptest.NewRecorder()

	s.handlePollCommands(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleCommandResult(t *testing.T) {
	s := newTestServer("")

	s.commands.mu.Lock()
	s.commands.commands["cmd-1"] = &Command{ID: "cmd-1", Status: "dispatched"}
	s.commands.mu.Unlock()

	body := `{"command_id":"cmd-1","output":"scan complete","success":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/commands/result", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleCommandResult(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	s.commands.mu.RLock()
	cmd := s.commands.commands["cmd-1"]
	s.commands.mu.RUnlock()

	if cmd.Status != "completed" {
		t.Errorf("status = %q, want %q", cmd.Status, "completed")
	}
	if cmd.Output != "scan complete" {
		t.Errorf("output = %q, want %q", cmd.Output, "scan complete")
	}
}

func TestHandleCommandResultFailed(t *testing.T) {
	s := newTestServer("")

	s.commands.mu.Lock()
	s.commands.commands["cmd-2"] = &Command{ID: "cmd-2", Status: "dispatched"}
	s.commands.mu.Unlock()

	body := `{"command_id":"cmd-2","output":"error occurred","success":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/commands/result", strings.NewReader(body))
	w := httptest.NewRecorder()

	s.handleCommandResult(w, req)

	s.commands.mu.RLock()
	cmd := s.commands.commands["cmd-2"]
	s.commands.mu.RUnlock()

	if cmd.Status != "failed" {
		t.Errorf("status = %q, want %q", cmd.Status, "failed")
	}
}

func TestAuthMiddlewareDisabled(t *testing.T) {
	s := newTestServer("")
	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler not called when auth is disabled")
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	s := newTestServer("my-token")
	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer my-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler not called with valid token")
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	s := newTestServer("my-token")
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid token")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareNoCredentials(t *testing.T) {
	s := newTestServer("my-token")
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without credentials")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddlewareValidSession(t *testing.T) {
	s := newTestServer("my-token")
	sessionID := s.sessions.create("my-token")

	called := false
	handler := s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler not called with valid session cookie")
	}
}

func TestLoginPostJSON(t *testing.T) {
	s := newTestServer("secret-token")

	body := `{"token":"secret-token"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleLoginPost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "authenticated" {
		t.Errorf("status = %q, want %q", resp["status"], "authenticated")
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("session cookie not set after login")
	}
}

func TestLoginPostForm(t *testing.T) {
	s := newTestServer("secret-token")

	form := url.Values{"token": []string{"secret-token"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.handleLoginPost(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d (redirect)", w.Code, http.StatusSeeOther)
	}
}

func TestLoginPostInvalidToken(t *testing.T) {
	s := newTestServer("secret-token")

	body := `{"token":"wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleLoginPost(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLogout(t *testing.T) {
	s := newTestServer("secret-token")
	sessionID := s.sessions.create("secret-token")

	req := httptest.NewRequest(http.MethodDelete, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})
	w := httptest.NewRecorder()

	s.handleLogout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if s.sessions.valid(sessionID) {
		t.Error("session still valid after logout")
	}

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "session" && c.MaxAge != -1 {
			t.Error("session cookie not cleared")
		}
	}
}

func TestDashboardAuthRedirectsToLogin(t *testing.T) {
	s := newTestServer("secret-token")
	called := false
	handler := s.dashboardAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("dashboard handler should not be called without auth")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected login page (200), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "login") && !strings.Contains(w.Body.String(), "Login") && !strings.Contains(w.Body.String(), "KUBEDAGGER") {
		t.Error("expected login page content")
	}
}

func TestSessionStore(t *testing.T) {
	ss := newSessionStore()

	id := ss.create("tok")
	if id == "" {
		t.Fatal("session ID is empty")
	}
	if !ss.valid(id) {
		t.Error("newly created session should be valid")
	}

	ss.delete(id)
	if ss.valid(id) {
		t.Error("deleted session should be invalid")
	}

	if ss.valid("nonexistent") {
		t.Error("nonexistent session should be invalid")
	}
}

func TestHandleCommandsEmpty(t *testing.T) {
	s := newTestServer("")
	req := httptest.NewRequest(http.MethodGet, "/api/commands", nil)
	w := httptest.NewRecorder()

	s.handleCommands(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var cmds []Command
	if err := json.NewDecoder(w.Body).Decode(&cmds); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cmds) != 0 {
		t.Errorf("expected 0 commands, got %d", len(cmds))
	}
}

func TestFullWorkflow(t *testing.T) {
	s := newTestServer("")

	// Register agent
	regBody := `{"id":"agent-1","hostname":"node-1","os":"linux","arch":"amd64"}`
	req := httptest.NewRequest(http.MethodPost, "/api/agents/register", strings.NewReader(regBody))
	w := httptest.NewRecorder()
	s.handleAgentRegister(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("register: status = %d", w.Code)
	}

	// Create command
	cmdBody := `{"agent_id":"agent-1","module":"scan"}`
	req = httptest.NewRequest(http.MethodPost, "/api/commands/new", strings.NewReader(cmdBody))
	w = httptest.NewRecorder()
	s.handleNewCommand(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("new command: status = %d", w.Code)
	}
	var cmd Command
	_ = json.NewDecoder(w.Body).Decode(&cmd)

	// Poll
	req = httptest.NewRequest(http.MethodGet, "/api/commands/poll?agent_id=agent-1", nil)
	w = httptest.NewRecorder()
	s.handlePollCommands(w, req)
	var polled []*Command
	_ = json.NewDecoder(w.Body).Decode(&polled)
	if len(polled) != 1 {
		t.Fatalf("poll: expected 1 command, got %d", len(polled))
	}

	// Submit result
	result := map[string]any{"command_id": cmd.ID, "output": "done", "success": true}
	resultBytes, _ := json.Marshal(result)
	req = httptest.NewRequest(http.MethodPost, "/api/commands/result", bytes.NewReader(resultBytes))
	w = httptest.NewRecorder()
	s.handleCommandResult(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("result: status = %d", w.Code)
	}

	// Verify final state
	s.commands.mu.RLock()
	final := s.commands.commands[cmd.ID]
	s.commands.mu.RUnlock()
	if final.Status != "completed" {
		t.Errorf("final status = %q, want %q", final.Status, "completed")
	}
}

// seedEvents records the given events into the server's event store.
func seedEvents(t *testing.T, s *Server, evs ...events.Event) {
	t.Helper()
	for _, e := range evs {
		if err := s.events.Record(e); err != nil {
			t.Fatalf("record event: %v", err)
		}
	}
}

// seedReplayEvents records count events whose techniques and details carry a
// 1-based index (e.g. "replay-step-3") so pages can be asserted positionally.
func seedReplayEvents(t *testing.T, s *Server, count int) {
	t.Helper()
	for i := 1; i <= count; i++ {
		seedEvents(t, s, events.Event{
			AgentID:   "agent-1",
			Type:      events.TypeTaskResult,
			Technique: "replay-step-" + strconv.Itoa(i),
			Status:    "ok",
			Detail:    "detail for event " + strconv.Itoa(i),
		})
	}
}

func TestNewServerWithEventsNilStore(t *testing.T) {
	s := NewServerWithEvents(":0", "", nil)
	if s.events == nil {
		t.Fatal("events store is nil")
	}
	if s.events.Count() != 0 {
		t.Errorf("expected 0 events, got %d", s.events.Count())
	}

	// The memory-only store must be usable: recording and rendering must not panic.
	seedEvents(t, s, events.Event{Type: events.TypeAgentCheckin, AgentID: "agent-1", Technique: "nil-store-check"})
	req := httptest.NewRequest(http.MethodGet, "/campaign", nil)
	w := httptest.NewRecorder()
	s.handleCampaign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "nil-store-check") {
		t.Error("expected seeded event to render with nil store fallback")
	}
}

func TestNewServerWithEventsSharedStore(t *testing.T) {
	store, err := events.NewStore("")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := store.Record(events.Event{AgentID: "agent-9", Technique: "shared-store-check"}); err != nil {
		t.Fatalf("record: %v", err)
	}

	s := NewServerWithEvents(":0", "", store)
	if s.events != store {
		t.Error("server should use the provided store")
	}
	if s.events.Count() != 1 {
		t.Errorf("expected 1 event, got %d", s.events.Count())
	}

	req := httptest.NewRequest(http.MethodGet, "/campaign", nil)
	w := httptest.NewRecorder()
	s.handleCampaign(w, req)
	if !strings.Contains(w.Body.String(), "shared-store-check") {
		t.Error("expected shared store event to render")
	}
}

func TestNewServerMemoryOnlyStore(t *testing.T) {
	s := newTestServer("")
	if s.events == nil {
		t.Fatal("NewServer should create a memory-only events store")
	}
	if s.auth.Enabled {
		t.Error("auth should be disabled with empty token")
	}
}

func TestHandleCampaign(t *testing.T) {
	s := newTestServer("")
	seedEvents(t, s,
		events.Event{
			AgentID:   "agent-1",
			Type:      events.TypeTaskSubmitted,
			Technique: "k8s_secrets",
			TaskType:  "cloud_evasion",
			Status:    "completed",
			MITRE:     "T1552.001",
			Detail:    "listed secrets in default namespace",
			Payload:   map[string]string{"namespace": "default"},
		},
		events.Event{
			AgentID:   "agent-2",
			Type:      events.TypeAgentCheckin,
			Technique: "beacon",
			Status:    "active",
			Detail:    "agent checked in",
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/campaign", nil)
	w := httptest.NewRecorder()
	s.handleCampaign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	for _, want := range []string{"k8s_secrets", "T1552.001", "agent-1", "agent-2", "2 events"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestHandleCampaignFilters(t *testing.T) {
	s := newTestServer("")
	seedEvents(t, s,
		events.Event{AgentID: "agent-alpha", Type: events.TypeTaskSubmitted, Technique: "technique-alpha", Detail: "alpha task"},
		events.Event{AgentID: "agent-beta", Type: events.TypeAgentCheckin, Technique: "technique-beta", Detail: "beta checkin"},
	)

	tests := []struct {
		name        string
		query       string
		wantBody    []string
		notWantBody []string
	}{
		{
			name:     "no filter shows all events",
			query:    "",
			wantBody: []string{"technique-alpha", "technique-beta"},
		},
		{
			name:        "agent filter matches substring",
			query:       "?agent=alpha",
			wantBody:    []string{"technique-alpha"},
			notWantBody: []string{"technique-beta"},
		},
		{
			name:        "agent filter is case-insensitive",
			query:       "?agent=ALPHA",
			wantBody:    []string{"technique-alpha"},
			notWantBody: []string{"technique-beta"},
		},
		{
			name:        "type filter narrows to checkins",
			query:       "?type=agent_checkin",
			wantBody:    []string{"technique-beta"},
			notWantBody: []string{"technique-alpha"},
		},
		{
			name:     "type filter all shows everything",
			query:    "?type=all",
			wantBody: []string{"technique-alpha", "technique-beta"},
		},
		{
			name:        "combined filters",
			query:       "?agent=beta&type=task_submitted",
			wantBody:    []string{"no events match the current filters"},
			notWantBody: []string{"technique-alpha", "technique-beta"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/campaign"+tt.query, nil)
			w := httptest.NewRecorder()
			s.handleCampaign(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			body := w.Body.String()
			for _, want := range tt.wantBody {
				if !strings.Contains(body, want) {
					t.Errorf("body missing %q", want)
				}
			}
			for _, notWant := range tt.notWantBody {
				if strings.Contains(body, notWant) {
					t.Errorf("body unexpectedly contains %q", notWant)
				}
			}
		})
	}
}

func TestHandleCampaignLimit(t *testing.T) {
	s := newTestServer("")
	seedReplayEvents(t, s, 5)

	tests := []struct {
		name  string
		query string
		want  int
	}{
		{name: "default limit covers all", query: "", want: 5},
		{name: "explicit limit", query: "?limit=2", want: 2},
		{name: "limit of zero falls back to default", query: "?limit=0", want: 5},
		{name: "negative limit falls back to default", query: "?limit=-3", want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/campaign"+tt.query, nil)
			w := httptest.NewRecorder()
			s.handleCampaign(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			body := w.Body.String()
			if !strings.Contains(body, "showing "+strconv.Itoa(tt.want)+" of 5 events") {
				t.Errorf("expected note showing %d of 5 events, body: %s", tt.want, body)
			}
		})
	}
}

func TestHandleCampaignLimitCap(t *testing.T) {
	s := newTestServer("")
	seedReplayEvents(t, s, 3)

	req := httptest.NewRequest(http.MethodGet, "/campaign?limit=9999", nil)
	w := httptest.NewRecorder()
	s.handleCampaign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	// The requested limit is capped at 1000 and echoed back in the form.
	if !strings.Contains(body, `value="1000"`) {
		t.Error("expected limit to be capped at 1000")
	}
	if !strings.Contains(body, "showing 3 of 3 events") {
		t.Error("expected all 3 events to render")
	}
}

func TestHandleCampaignDetailTruncation(t *testing.T) {
	s := newTestServer("")
	long := strings.Repeat("x", 250)
	seedEvents(t, s, events.Event{AgentID: "agent-1", Type: events.TypeTaskResult, Technique: "long-detail", Detail: long})

	req := httptest.NewRequest(http.MethodGet, "/campaign", nil)
	w := httptest.NewRecorder()
	s.handleCampaign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	// Truncated cell plus full text in the title attribute.
	if !strings.Contains(body, `title="`+long+`"`) {
		t.Error("expected full detail in title attribute")
	}
	if strings.Contains(body, ">"+long+"<") {
		t.Error("expected detail cell to be truncated")
	}
	if !strings.Contains(body, strings.Repeat("x", 100)+"...") {
		t.Error("expected truncated detail of 100 runes plus ellipsis")
	}
}

func TestHandleCampaignEmpty(t *testing.T) {
	s := newTestServer("")

	req := httptest.NewRequest(http.MethodGet, "/campaign", nil)
	w := httptest.NewRecorder()
	s.handleCampaign(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "no events recorded yet") {
		t.Error("expected empty-state message")
	}
}

func TestHandleReplay(t *testing.T) {
	s := newTestServer("")
	seedEvents(t, s, events.Event{
		AgentID:   "agent-1",
		Type:      events.TypeTaskResult,
		Technique: "k8s_secrets",
		TaskType:  "cloud_evasion",
		Status:    "completed",
		MITRE:     "T1552.001",
		Detail:    "listed secrets",
		Payload:   map[string]string{"namespace": "default", "count": "3"},
	})

	req := httptest.NewRequest(http.MethodGet, "/replay", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	for _, want := range []string{"k8s_secrets", "T1552.001", "cloud_evasion", "listed secrets", "namespace", "default", "showing 1&ndash;1 of 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestHandleReplaySlicing(t *testing.T) {
	s := newTestServer("")
	seedReplayEvents(t, s, 10)

	req := httptest.NewRequest(http.MethodGet, "/replay?offset=2&step=3", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	// Events 3-5 (indices 2-4) should appear.
	for _, want := range []string{"replay-step-3", "replay-step-4", "replay-step-5", "showing 3&ndash;5 of 10"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	for _, notWant := range []string{"replay-step-2", "replay-step-6", "replay-step-1", "replay-step-10"} {
		if strings.Contains(body, notWant) {
			t.Errorf("body unexpectedly contains %q", notWant)
		}
	}
}

func TestHandleReplayNavigation(t *testing.T) {
	s := newTestServer("")
	seedReplayEvents(t, s, 10)

	tests := []struct {
		name         string
		query        string
		wantNewerURI string // empty means Newer must be disabled
		wantOlderURI string // empty means Older must be disabled
		wantPosition string
	}{
		{
			name:         "start disables newer, enables older",
			query:        "?step=3",
			wantOlderURI: "/replay?offset=3&amp;step=3",
			wantPosition: "showing 1&ndash;3 of 10",
		},
		{
			name:         "middle enables both",
			query:        "?offset=3&step=3",
			wantNewerURI: "/replay?offset=0&amp;step=3",
			wantOlderURI: "/replay?offset=6&amp;step=3",
			wantPosition: "showing 4&ndash;6 of 10",
		},
		{
			name:         "end disables older",
			query:        "?offset=7&step=3",
			wantNewerURI: "/replay?offset=4&amp;step=3",
			wantPosition: "showing 8&ndash;10 of 10",
		},
		{
			name:         "newer link never goes below zero",
			query:        "?offset=1&step=3",
			wantNewerURI: "/replay?offset=0&amp;step=3",
			wantOlderURI: "/replay?offset=4&amp;step=3",
			wantPosition: "showing 2&ndash;4 of 10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/replay"+tt.query, nil)
			w := httptest.NewRecorder()
			s.handleReplay(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			body := w.Body.String()

			if !strings.Contains(body, tt.wantPosition) {
				t.Errorf("position %q missing from body", tt.wantPosition)
			}

			// Both controls always render; each is either a link or a disabled span.
			if tt.wantNewerURI == "" {
				if !strings.Contains(body, `class="btn disabled">&larr; Newer`) {
					t.Error("expected disabled Newer control")
				}
			} else if !strings.Contains(body, `href="`+tt.wantNewerURI+`"`) {
				t.Errorf("expected Newer link %q", tt.wantNewerURI)
			}

			if tt.wantOlderURI == "" {
				if !strings.Contains(body, `class="btn disabled">Older`) {
					t.Error("expected disabled Older control")
				}
			} else if !strings.Contains(body, `href="`+tt.wantOlderURI+`"`) {
				t.Errorf("expected Older link %q", tt.wantOlderURI)
			}
		})
	}
}

func TestHandleReplayNegativeOffsetClamps(t *testing.T) {
	s := newTestServer("")
	seedReplayEvents(t, s, 10)

	req := httptest.NewRequest(http.MethodGet, "/replay?offset=-5&step=2", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "showing 1&ndash;2 of 10") {
		t.Error("negative offset should clamp to 0 and show events 1-2")
	}
	if !strings.Contains(body, "replay-step-1") || !strings.Contains(body, "replay-step-2") {
		t.Error("expected first two events after clamping")
	}
	if strings.Contains(body, "replay-step-3") {
		t.Error("negative offset should not show events past the step window")
	}
}

func TestHandleReplayStepBounds(t *testing.T) {
	s := newTestServer("")
	seedReplayEvents(t, s, 60)

	tests := []struct {
		name     string
		query    string
		position string
	}{
		{name: "default step is 1", query: "", position: "showing 1&ndash;1 of 60"},
		{name: "step is capped at 50", query: "?step=500", position: "showing 1&ndash;50 of 60"},
		{name: "non-numeric step falls back to default", query: "?step=abc", position: "showing 1&ndash;1 of 60"},
		{name: "non-positive step falls back to default", query: "?step=0", position: "showing 1&ndash;1 of 60"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/replay"+tt.query, nil)
			w := httptest.NewRecorder()
			s.handleReplay(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}
			if !strings.Contains(w.Body.String(), tt.position) {
				t.Errorf("expected %q in body", tt.position)
			}
		})
	}
}

func TestHandleReplayEmpty(t *testing.T) {
	s := newTestServer("")

	req := httptest.NewRequest(http.MethodGet, "/replay", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "no events recorded yet") {
		t.Error("expected empty-state message")
	}
	if !strings.Contains(body, "showing 0&ndash;0 of 0") {
		t.Error("expected zero position indicator")
	}
}
