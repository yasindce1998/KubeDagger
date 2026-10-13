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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDetectCloudSecurity_AllProviders(t *testing.T) {
	tests := []struct {
		name          string
		handler       http.HandlerFunc
		wantName      string
		wantDetection bool
	}{
		{
			name: "AWS IMDSv2 flow",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/latest/api/token":
					if r.Method != http.MethodPut {
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte("test-imds-token"))
				case "/latest/meta-data/":
					if r.Header.Get("X-aws-ec2-metadata-token") != "test-imds-token" {
						http.Error(w, "missing token", http.StatusUnauthorized)
						return
					}
					w.Write([]byte("ami-id\ninstance-id\n"))
				default:
					http.NotFound(w, r)
				}
			},
			wantName:      "cloud-metadata-aws",
			wantDetection: true,
		},
		{
			name: "AWS IMDSv1 fallback",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/latest/api/token":
					http.Error(w, "token disabled", http.StatusForbidden)
				case "/latest/meta-data/":
					w.Write([]byte("instance-id\n"))
				default:
					http.NotFound(w, r)
				}
			},
			wantName:      "cloud-metadata-aws",
			wantDetection: true,
		},
		{
			name: "AWS IMDS not reachable (404 on metadata)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
			wantName:      "cloud-metadata-aws",
			wantDetection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			systems := DetectCloudSecurity(context.Background(), serverTimeoutClient(),
				CloudEndpoints{AWS: server.URL, Azure: "http://127.0.0.1:1", GCP: "http://127.0.0.1:1"})

			if len(systems) != 3 {
				t.Fatalf("expected 3 systems, got %d", len(systems))
			}

			aws := findSystem(systems, tt.wantName)
			if aws == nil {
				t.Fatalf("expected %s in results", tt.wantName)
			}
			if aws.Detected != tt.wantDetection {
				t.Errorf("expected detected=%v, got %v (details: %s)", tt.wantDetection, aws.Detected, aws.Details)
			}
			if tt.wantDetection && aws.Details == "not reachable" {
				t.Error("expected details to describe the detection")
			}
			if !tt.wantDetection && aws.Details != "not reachable" {
				t.Errorf("expected 'not reachable' details, got %q", aws.Details)
			}
			if tt.wantDetection {
				checkContains(t, aws.Details, "GuardDuty")
			}
		})
	}
}

func TestDetectCloudSecurity_Azure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "metadata header required", http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"compute":{"azEnvironment":"AzurePublicCloud"}}`))
	}))
	defer server.Close()

	systems := DetectCloudSecurity(context.Background(), serverTimeoutClient(),
		CloudEndpoints{AWS: "http://127.0.0.1:1", Azure: server.URL, GCP: "http://127.0.0.1:1"})

	azure := findSystem(systems, "cloud-metadata-azure")
	if azure == nil {
		t.Fatal("expected cloud-metadata-azure in results")
	}
	if !azure.Detected {
		t.Fatalf("expected azure metadata detected, details: %s", azure.Details)
	}
	checkContains(t, azure.Details, "Defender for Cloud")
	checkContains(t, azure.Details, "168.63.129.16")

	// The unreachable providers must be reported as not detected.
	if aws := findSystem(systems, "cloud-metadata-aws"); aws == nil || aws.Detected {
		t.Error("expected AWS to be present and not detected")
	}
	if gcp := findSystem(systems, "cloud-metadata-gcp"); gcp == nil || gcp.Detected {
		t.Error("expected GCP to be present and not detected")
	}
}

func TestDetectCloudSecurity_GCP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "flavor header required", http.StatusBadRequest)
			return
		}
		w.Write([]byte("instance/\nproject/\n"))
	}))
	defer server.Close()

	systems := DetectCloudSecurity(context.Background(), serverTimeoutClient(),
		CloudEndpoints{AWS: "http://127.0.0.1:1", Azure: "http://127.0.0.1:1", GCP: server.URL})

	gcp := findSystem(systems, "cloud-metadata-gcp")
	if gcp == nil {
		t.Fatal("expected cloud-metadata-gcp in results")
	}
	if !gcp.Detected {
		t.Fatalf("expected gcp metadata detected, details: %s", gcp.Details)
	}
	checkContains(t, gcp.Details, "Security Command Center")
}

func TestDetectCloudSecurity_AllUnreachable(t *testing.T) {
	// Nothing listens on this port; every provider must be reported as not
	// detected rather than erroring.
	endpoints := CloudEndpoints{
		AWS:   "http://127.0.0.1:1",
		Azure: "http://127.0.0.1:1",
		GCP:   "http://127.0.0.1:1",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	systems := DetectCloudSecurity(ctx, serverTimeoutClient(), endpoints)
	if len(systems) != 3 {
		t.Fatalf("expected 3 systems, got %d", len(systems))
	}
	for _, s := range systems {
		if s.Detected {
			t.Errorf("expected %s to not be detected", s.Name)
		}
		if s.Details != "not reachable" {
			t.Errorf("expected 'not reachable' details for %s, got %q", s.Name, s.Details)
		}
	}
}

func TestFormatCloudDetections(t *testing.T) {
	systems := []DetectionSystem{
		{Name: "cloud-metadata-aws", Detected: true, Details: "reachable"},
		{Name: "cloud-metadata-gcp", Detected: false, Details: "not reachable"},
	}
	out := FormatCloudDetections(systems)
	checkContains(t, out, "[ACTIVE] cloud-metadata-aws")
	checkContains(t, out, "[not detected] cloud-metadata-gcp")
}

func serverTimeoutClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

func findSystem(systems []DetectionSystem, name string) *DetectionSystem {
	for i := range systems {
		if systems[i].Name == name {
			return &systems[i]
		}
	}
	return nil
}

func checkContains(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("expected %q to contain %q", s, sub)
	}
}
