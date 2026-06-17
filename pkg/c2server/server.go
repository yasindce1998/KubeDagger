package c2server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type ServerConfig struct {
	ListenAddr string
	TLSConfig  *tls.Config
}

type Server struct {
	config   ServerConfig
	httpSrv  *http.Server
	agents   *AgentRegistry
	tasks    *TaskQueue
	handlers *Handlers
}

func NewServer(cfg ServerConfig) *Server {
	agents := NewAgentRegistry()
	tasks := NewTaskQueue()
	handlers := NewHandlers(agents, tasks)

	mux := http.NewServeMux()
	mux.HandleFunc("/checkin", handlers.HandleCheckin)
	mux.HandleFunc("/task", handlers.HandleTask)
	mux.HandleFunc("/result", handlers.HandleResult)

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		TLSConfig:    cfg.TLSConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return &Server{
		config:   cfg,
		httpSrv:  srv,
		agents:   agents,
		tasks:    tasks,
		handlers: handlers,
	}
}

func (s *Server) Agents() *AgentRegistry {
	return s.agents
}

func (s *Server) Tasks() *TaskQueue {
	return s.tasks
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
	return s.httpSrv.Shutdown(ctx)
}
