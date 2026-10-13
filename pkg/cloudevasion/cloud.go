/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cloudevasion

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudEndpoints holds the base URLs of the cloud instance metadata
// services. Empty fields fall back to the real link-local endpoints; tests
// can point them at httptest servers.
type CloudEndpoints struct {
	AWS   string
	Azure string
	GCP   string
}

const (
	defaultAWSEndpoint   = "http://169.254.169.254"
	defaultAzureEndpoint = "http://169.254.169.254/metadata/instance"
	defaultGCPEndpoint   = "http://metadata.google.internal"

	cloudProbeTimeout = 2 * time.Second
)

// DetectCloudSecurity probes the AWS, Azure, and GCP instance metadata
// services reachable from the current host and reports each one as a
// DetectionSystem, including notes on the cloud provider's detection
// telemetry. All probes are best-effort: network errors are reported as
// "not reachable", never as failures.
func DetectCloudSecurity(ctx context.Context, httpClient *http.Client, endpoints CloudEndpoints) []DetectionSystem {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if endpoints.AWS == "" {
		endpoints.AWS = defaultAWSEndpoint
	}
	if endpoints.Azure == "" {
		endpoints.Azure = defaultAzureEndpoint
	}
	if endpoints.GCP == "" {
		endpoints.GCP = defaultGCPEndpoint
	}

	return []DetectionSystem{
		detectAWSMetadata(ctx, httpClient, endpoints.AWS),
		detectAzureMetadata(ctx, httpClient, endpoints.Azure),
		detectGCPMetadata(ctx, httpClient, endpoints.GCP),
	}
}

func detectAWSMetadata(ctx context.Context, client *http.Client, base string) DetectionSystem {
	system := DetectionSystem{
		Name:    "cloud-metadata-aws",
		Details: "not reachable",
	}

	// IMDSv2: request a session token first; if the token endpoint responds,
	// use token-based access (the evasion-aware pattern).
	reqCtx, cancel := context.WithTimeout(ctx, cloudProbeTimeout)
	defer cancel()

	token := ""
	tokenReq, err := http.NewRequestWithContext(reqCtx, http.MethodPut, strings.TrimSuffix(base, "/")+"/latest/api/token", nil)
	if err != nil {
		return system
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	if resp, err := client.Do(tokenReq); err == nil {
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			if len(body) > 0 {
				token = string(body)
			}
		} else {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	metaReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimSuffix(base, "/")+"/latest/meta-data/", nil)
	if err != nil {
		return system
	}
	if token != "" {
		metaReq.Header.Set("X-aws-ec2-metadata-token", token)
	}

	resp, err := client.Do(metaReq)
	if err != nil {
		return system
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return system
	}

	system.Detected = true
	system.Details = "AWS EC2 instance metadata service (IMDS) reachable" +
		" — note: GuardDuty monitors IMDS anomaly volume and canary credentials;" +
		" prefer token-based IMDSv2 usage patterns to blend in"
	return system
}

func detectAzureMetadata(ctx context.Context, client *http.Client, base string) DetectionSystem {
	system := DetectionSystem{
		Name:    "cloud-metadata-azure",
		Details: "not reachable",
	}

	reqCtx, cancel := context.WithTimeout(ctx, cloudProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, base, nil)
	if err != nil {
		return system
	}
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return system
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return system
	}

	system.Detected = true
	system.Details = "Azure Instance Metadata Service (IMDS) reachable" +
		" — note: Microsoft Defender for Cloud correlates telemetry from VM agents and metadata access;" +
		" the wireserver at 168.63.129.16 is another Azure-specific channel to be aware of"
	return system
}

func detectGCPMetadata(ctx context.Context, client *http.Client, base string) DetectionSystem {
	system := DetectionSystem{
		Name:    "cloud-metadata-gcp",
		Details: "not reachable",
	}

	reqCtx, cancel := context.WithTimeout(ctx, cloudProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimSuffix(base, "/")+"/computeMetadata/v1/", nil)
	if err != nil {
		return system
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return system
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return system
	}

	system.Detected = true
	system.Details = "GCE instance metadata server reachable" +
		" — note: Google Security Command Center aggregates audit logs and metadata access anomalies"
	return system
}

// FormatCloudDetections renders cloud metadata probe results as a readable
// report (distinct from the cluster-focused FormatSystems).
func FormatCloudDetections(systems []DetectionSystem) string {
	var sb strings.Builder
	sb.WriteString("Cloud security detection report:\n")
	for _, s := range systems {
		status := "not detected"
		if s.Detected {
			status = "ACTIVE"
		}
		fmt.Fprintf(&sb, "  [%s] %s — %s\n", status, s.Name, s.Details)
	}
	return sb.String()
}
