package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/internal/listenpolicy"
	"github.com/yasindce1998/KubeDagger/pkg/agent/stealth"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
	"github.com/yasindce1998/KubeDagger/pkg/events"
	"github.com/yasindce1998/KubeDagger/pkg/kubedagger/c2"
	"github.com/yasindce1998/KubeDagger/pkg/malleable"
	"github.com/yasindce1998/KubeDagger/pkg/scope"
	"github.com/yasindce1998/KubeDagger/pkg/webui"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	var (
		listenAddr  = flag.String("listen", "0.0.0.0:443", "HTTP/2 listener address for agents")
		mgmtAddr    = flag.String("mgmt", "127.0.0.1:9443", "management port for operator CLI")
		keyHex      = flag.String("key", "", "shared encryption key (hex) for management port")
		tlsCA       = flag.String("ca", "", "path to CA cert PEM (auto-generate if empty)")
		tlsCert     = flag.String("cert", "", "path to server cert PEM")
		tlsKey      = flag.String("key-file", "", "path to server key PEM")
		plaintext   = flag.Bool("plaintext", false, "disable TLS (development only)")
		logLevel    = flag.String("log-level", "info", "log level (debug, info, warn, error)")
		profile     = flag.String("profile", "legacy", "endpoint profile: legacy, telemetry, cdn, webhook")
		rateLimit   = flag.Float64("rate-limit", 0, "requests per second per IP (0 = disabled)")
		rateBurst   = flag.Int("rate-burst", 0, "rate limit burst (default: 2x rate-limit)")
		obfuscKey   = flag.String("obfusc-key", "", "shared secret for payload obfuscation")
		psk         = flag.String("psk", "", "pre-shared key for agent auth (X-Api-Key)")
		eventsPath  = flag.String("events", "", "path to JSONL event log (enables structured telemetry, report generation, and web UI campaign views)")
		scopePath   = flag.String("scope", "", "path to scope policy YAML (allowed namespaces/domains/CIDRs; tasks outside scope are rejected)")
		mallPath    = flag.String("malleable", "", "path to malleable C2 profile YAML (beacon sleep/jitter/User-Agent)")
		webuiAddr   = flag.String("webui", "", "start the web UI (campaign timeline + replay) on this address (e.g. 127.0.0.1:8080; empty = disabled)")
		webuiToken  = flag.String("webui-token", "", "required web UI authentication token (or KUBEDAGGER_WEBUI_TOKEN)")
		webuiCert   = flag.String("webui-cert", "", "web UI HTTPS certificate PEM (required for non-loopback listeners)")
		webuiKey    = flag.String("webui-key", "", "web UI HTTPS key PEM")
		webuiSecure = flag.Bool("webui-secure-cookies", false, "require HTTPS session cookies behind a TLS reverse proxy")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("kubedagger-server %s\n", version)
		return
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("invalid log level: %v", err)
	}
	logrus.SetLevel(level)
	if *plaintext && !listenpolicy.IsLoopback(*listenAddr) {
		logrus.Fatal("plaintext development mode must bind to a literal loopback address (e.g. -listen 127.0.0.1:8443)")
	}
	if *webuiToken == "" {
		*webuiToken = os.Getenv("KUBEDAGGER_WEBUI_TOKEN")
	}

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

	var ui *webui.Server
	if *webuiAddr != "" {
		opts := []webui.Option{webui.WithScope(cfg.Scope), webui.WithTLSFiles(*webuiCert, *webuiKey)}
		if *webuiSecure {
			opts = append(opts, webui.WithSecureCookies())
		}
		ui = webui.NewServerWithEvents(*webuiAddr, *webuiToken, cfg.Events, opts...)
		if err := ui.ValidateConfig(); err != nil {
			logrus.Fatalf("web UI configuration: %v", err)
		}
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
		defer mgmt.Stop()
	}

	uiCtx, stopUI := context.WithCancel(context.Background())
	defer stopUI()
	var uiDone chan error
	if ui != nil {
		uiDone = make(chan error, 1)
		go func(done chan<- error) {
			done <- ui.Start(uiCtx)
		}(uiDone)
		scheme := "http"
		if *webuiCert != "" {
			scheme = "https"
		}
		logrus.Infof("web UI (campaign/replay) on %s://%s", scheme, *webuiAddr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	select {
	case <-sig:
	case err := <-uiDone:
		if err != nil && err != http.ErrServerClosed {
			logrus.Errorf("web UI failed: %v", err)
		}
		uiDone = nil
	}

	logrus.Info("shutting down...")
	stopUI()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Stop(ctx)
	if uiDone != nil {
		select {
		case <-uiDone:
		case <-ctx.Done():
		}
	}
}
