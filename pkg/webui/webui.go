package webui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	addr     string
	agents   *AgentStore
	commands *CommandQueue
	mux      *http.ServeMux
	server   *http.Server
}

type AgentInfo struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	IP           string    `json:"ip"`
	OS           string    `json:"os"`
	Arch         string    `json:"arch"`
	Cluster      string    `json:"cluster"`
	Namespace    string    `json:"namespace"`
	Pod          string    `json:"pod"`
	LastSeen     time.Time `json:"last_seen"`
	Modules      []string  `json:"modules"`
	Status       string    `json:"status"`
}

type Command struct {
	ID        string            `json:"id"`
	AgentID   string            `json:"agent_id"`
	Module    string            `json:"module"`
	Args      map[string]string `json:"args"`
	Status    string            `json:"status"`
	Output    string            `json:"output"`
	CreatedAt time.Time         `json:"created_at"`
	DoneAt    time.Time         `json:"done_at,omitempty"`
}

type AgentStore struct {
	mu     sync.RWMutex
	agents map[string]*AgentInfo
}

type CommandQueue struct {
	mu       sync.RWMutex
	commands map[string]*Command
	pending  map[string][]*Command
}

func NewServer(addr string) *Server {
	s := &Server{
		addr: addr,
		agents: &AgentStore{
			agents: make(map[string]*AgentInfo),
		},
		commands: &CommandQueue{
			commands: make(map[string]*Command),
			pending:  make(map[string][]*Command),
		},
		mux: http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Start(ctx context.Context) error {
	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	return s.server.ListenAndServe()
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/", s.handleDashboard)
	s.mux.HandleFunc("/api/agents", s.handleAgents)
	s.mux.HandleFunc("/api/agents/register", s.handleAgentRegister)
	s.mux.HandleFunc("/api/commands", s.handleCommands)
	s.mux.HandleFunc("/api/commands/new", s.handleNewCommand)
	s.mux.HandleFunc("/api/commands/poll", s.handlePollCommands)
	s.mux.HandleFunc("/api/commands/result", s.handleCommandResult)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.agents.mu.RLock()
	agents := make([]*AgentInfo, 0, len(s.agents.agents))
	for _, a := range s.agents.agents {
		agents = append(agents, a)
	}
	s.agents.mu.RUnlock()

	s.commands.mu.RLock()
	commands := make([]*Command, 0, len(s.commands.commands))
	for _, c := range s.commands.commands {
		commands = append(commands, c)
	}
	s.commands.mu.RUnlock()

	data := map[string]any{
		"Agents":   agents,
		"Commands": commands,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

func (s *Server) handleAgents(w http.ResponseWriter, _ *http.Request) {
	s.agents.mu.RLock()
	defer s.agents.mu.RUnlock()

	agents := make([]*AgentInfo, 0, len(s.agents.agents))
	for _, a := range s.agents.agents {
		agents = append(agents, a)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(agents)
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var info AgentInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	info.LastSeen = time.Now()
	info.Status = "active"

	s.agents.mu.Lock()
	s.agents.agents[info.ID] = &info
	s.agents.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

func (s *Server) handleCommands(w http.ResponseWriter, _ *http.Request) {
	s.commands.mu.RLock()
	defer s.commands.mu.RUnlock()

	commands := make([]*Command, 0, len(s.commands.commands))
	for _, c := range s.commands.commands {
		commands = append(commands, c)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(commands)
}

func (s *Server) handleNewCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cmd Command
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cmd.ID = fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	cmd.Status = "pending"
	cmd.CreatedAt = time.Now()

	s.commands.mu.Lock()
	s.commands.commands[cmd.ID] = &cmd
	s.commands.pending[cmd.AgentID] = append(s.commands.pending[cmd.AgentID], &cmd)
	s.commands.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cmd)
}

func (s *Server) handlePollCommands(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}

	s.agents.mu.Lock()
	if a, ok := s.agents.agents[agentID]; ok {
		a.LastSeen = time.Now()
	}
	s.agents.mu.Unlock()

	s.commands.mu.Lock()
	pending := s.commands.pending[agentID]
	s.commands.pending[agentID] = nil
	for _, cmd := range pending {
		cmd.Status = "dispatched"
	}
	s.commands.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pending)
}

func (s *Server) handleCommandResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var result struct {
		CommandID string `json:"command_id"`
		Output    string `json:"output"`
		Success   bool   `json:"success"`
	}

	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.commands.mu.Lock()
	if cmd, ok := s.commands.commands[result.CommandID]; ok {
		cmd.Output = result.Output
		cmd.DoneAt = time.Now()
		if result.Success {
			cmd.Status = "completed"
		} else {
			cmd.Status = "failed"
		}
	}
	s.commands.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
