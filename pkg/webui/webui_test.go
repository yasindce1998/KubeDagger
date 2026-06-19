package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
