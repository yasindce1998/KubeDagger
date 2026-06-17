package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type K8sDiscovery struct{}

func (m *K8sDiscovery) Name() string        { return "k8s_discovery" }
func (m *K8sDiscovery) Platform() []string   { return []string{"linux", "windows", "darwin"} }

func (m *K8sDiscovery) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return &Result{Success: false, Output: "not running inside Kubernetes (KUBERNETES_SERVICE_HOST not set)"}, nil
	}

	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return &Result{Success: false, Output: fmt.Sprintf("cannot read service account token: %v", err)}, nil
	}

	baseURL := fmt.Sprintf("https://%s:%s", host, port)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	paths := []string{
		"/api/v1/namespaces",
		"/api/v1/pods",
		"/api/v1/secrets",
		"/api/v1/services",
		"/apis/apps/v1/deployments",
		"/apis/rbac.authorization.k8s.io/v1/clusterroles",
	}

	target := args["path"]
	if target != "" {
		paths = []string{target}
	}

	var results []string
	for _, path := range paths {
		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+string(token))

		resp, err := client.Do(req)
		if err != nil {
			results = append(results, fmt.Sprintf("%s: error: %v", path, err))
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		status := "DENIED"
		if resp.StatusCode == http.StatusOK {
			status = "ACCESSIBLE"
		}
		results = append(results, fmt.Sprintf("%s: %s (%d) [%d bytes]", path, status, resp.StatusCode, len(body)))
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("Kubernetes API: %s\n\n%s", baseURL, strings.Join(results, "\n")),
	}, nil
}
