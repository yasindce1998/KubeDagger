package webhook

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type WebhookResult struct {
	Action    string `json:"action"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Image     string `json:"image,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
}

type WebhookConfig struct {
	Name      string
	Namespace string
	Image     string
	CACert    []byte
	CAKey     *ecdsa.PrivateKey
}

func Deploy(namespace, image, output string) error {
	config, err := generateWebhookConfig(namespace, image)
	if err != nil {
		return fmt.Errorf("generate webhook config: %w", err)
	}

	result := &WebhookResult{
		Action:    "deploy",
		Name:      config.Name,
		Namespace: namespace,
		Image:     image,
		Status:    "configured",
		Detail:    fmt.Sprintf("MutatingWebhookConfiguration '%s' targeting namespace '%s' with init container image '%s'", config.Name, namespace, image),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func Remove(namespace, output string) error {
	result := &WebhookResult{
		Action:    "remove",
		Name:      "kube-node-validator",
		Namespace: namespace,
		Status:    "removed",
		Detail:    "MutatingWebhookConfiguration and associated service/deployment deleted",
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func generateWebhookConfig(namespace, image string) (*WebhookConfig, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   "kube-node-validator.kube-system.svc",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	return &WebhookConfig{
		Name:      "kube-node-validator",
		Namespace: namespace,
		Image:     image,
		CACert:    certPEM,
		CAKey:     key,
	}, nil
}

func GenerateMutationPayload(image string) map[string]interface{} {
	return map[string]interface{}{
		"op":   "add",
		"path": "/spec/initContainers/-",
		"value": map[string]interface{}{
			"name":  "node-validator",
			"image": image,
			"securityContext": map[string]interface{}{
				"privileged": true,
			},
			"volumeMounts": []map[string]interface{}{
				{
					"name":      "host-root",
					"mountPath": "/host",
				},
			},
		},
	}
}
