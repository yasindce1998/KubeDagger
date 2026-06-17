package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

func setupTLS(caPath, certPath, keyPath, _ string) (*tls.Config, []byte, error) {
	if certPath != "" && keyPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read CA: %w", err)
		}
		serverPair := &c2server.CertPair{
			CertPEM: mustReadFile(certPath),
			KeyPEM:  mustReadFile(keyPath),
		}
		tlsCfg, err := c2server.BuildServerTLSConfig(serverPair, caPEM)
		if err != nil {
			return nil, nil, err
		}
		return tlsCfg, caPEM, nil
	}

	logrus.Info("no certs provided, generating ephemeral CA and server cert")
	ca, caKey, caPair, err := c2server.GenerateCA()
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA: %w", err)
	}

	serverPair, err := c2server.GenerateServerCert(ca, caKey, []string{"localhost", "127.0.0.1", "0.0.0.0"})
	if err != nil {
		return nil, nil, fmt.Errorf("generate server cert: %w", err)
	}

	tlsCfg, err := c2server.BuildServerTLSConfig(serverPair, caPair.CertPEM)
	if err != nil {
		return nil, nil, err
	}

	logrus.Info("ephemeral CA generated — use -ca flag to provide persistent certs")
	return tlsCfg, caPair.CertPEM, nil
}

func mustReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		logrus.Fatalf("read %s: %v", path, err)
	}
	return data
}
