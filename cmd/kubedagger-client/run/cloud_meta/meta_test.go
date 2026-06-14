package cloud_meta

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchAWSWithMockIMDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			w.Write([]byte("mock-token"))
		case "/latest/meta-data/instance-id":
			w.Write([]byte("i-1234567890abcdef0"))
		case "/latest/meta-data/placement/region":
			w.Write([]byte("us-east-1"))
		case "/latest/meta-data/placement/availability-zone":
			w.Write([]byte("us-east-1a"))
		case "/latest/meta-data/hostname":
			w.Write([]byte("ip-10-0-0-1.ec2.internal"))
		case "/latest/meta-data/local-ipv4":
			w.Write([]byte("10.0.0.1"))
		case "/latest/meta-data/public-ipv4":
			w.Write([]byte("54.1.2.3"))
		case "/latest/meta-data/iam/security-credentials/":
			w.Write([]byte("test-role"))
		case "/latest/meta-data/iam/security-credentials/test-role":
			json.NewEncoder(w).Encode(map[string]string{
				"AccessKeyId":     "AKIAIOSFODNN7EXAMPLE",
				"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"Token":           "session-token-value",
				"Expiration":      "2026-06-15T12:00:00Z",
			})
		case "/latest/user-data":
			w.Write([]byte("#!/bin/bash\necho hello"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	origBase := imdsBase
	setIMDSBase(srv.URL)
	defer setIMDSBase(origBase)

	result, err := fetchAWS()
	if err != nil {
		t.Fatalf("fetchAWS failed: %v", err)
	}

	if result.Provider != ProviderAWS {
		t.Errorf("provider = %s, want aws", result.Provider)
	}
	if result.InstanceID != "i-1234567890abcdef0" {
		t.Errorf("instance_id = %s", result.InstanceID)
	}
	if result.Region != "us-east-1" {
		t.Errorf("region = %s", result.Region)
	}
	if result.PrivateIP != "10.0.0.1" {
		t.Errorf("private_ip = %s", result.PrivateIP)
	}
	if result.Credentials["access_key_id"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("access_key_id = %s", result.Credentials["access_key_id"])
	}
	if result.Credentials["role"] != "test-role" {
		t.Errorf("role = %s", result.Credentials["role"])
	}
}

func TestFetchGCPWithMockIMDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/computeMetadata/v1/instance/id":
			w.Write([]byte("123456789"))
		case "/computeMetadata/v1/instance/zone":
			w.Write([]byte("projects/123/zones/us-central1-a"))
		case "/computeMetadata/v1/instance/hostname":
			w.Write([]byte("test-vm.c.project.internal"))
		case "/computeMetadata/v1/instance/network-interfaces/0/ip":
			w.Write([]byte("10.128.0.2"))
		case "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip":
			w.Write([]byte("35.1.2.3"))
		case "/computeMetadata/v1/instance/service-accounts/default/token":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.example-token",
				"token_type":   "Bearer",
			})
		case "/computeMetadata/v1/instance/service-accounts/default/email":
			w.Write([]byte("sa@project.iam.gserviceaccount.com"))
		case "/computeMetadata/v1/instance/service-accounts/default/scopes":
			w.Write([]byte("https://www.googleapis.com/auth/cloud-platform"))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	origBase := imdsBase
	setIMDSBase(srv.URL)
	defer setIMDSBase(origBase)

	result, err := fetchGCP()
	if err != nil {
		t.Fatalf("fetchGCP failed: %v", err)
	}

	if result.Provider != ProviderGCP {
		t.Errorf("provider = %s, want gcp", result.Provider)
	}
	if result.InstanceID != "123456789" {
		t.Errorf("instance_id = %s", result.InstanceID)
	}
	if result.Region != "us-central1" {
		t.Errorf("region = %s, want us-central1", result.Region)
	}
	if result.Credentials["access_token"] != "ya29.example-token" {
		t.Errorf("access_token = %s", result.Credentials["access_token"])
	}
	if result.Credentials["service_account"] != "sa@project.iam.gserviceaccount.com" {
		t.Errorf("service_account = %s", result.Credentials["service_account"])
	}
}

func TestFetchAzureWithMockIMDS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/metadata/instance":
			json.NewEncoder(w).Encode(map[string]any{
				"compute": map[string]any{
					"vmId":     "vm-12345",
					"location": "eastus",
					"name":     "test-vm",
				},
				"network": map[string]any{
					"interface": []any{
						map[string]any{
							"ipv4": map[string]any{
								"ipAddress": []any{
									map[string]any{
										"privateIpAddress": "10.0.0.4",
										"publicIpAddress":  "20.1.2.3",
									},
								},
							},
						},
					},
				},
			})
		case "/metadata/identity/oauth2/token":
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.example",
				"token_type":   "Bearer",
				"resource":     "https://management.azure.com/",
			})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	origBase := imdsBase
	setIMDSBase(srv.URL)
	defer setIMDSBase(origBase)

	result, err := fetchAzure()
	if err != nil {
		t.Fatalf("fetchAzure failed: %v", err)
	}

	if result.Provider != ProviderAzure {
		t.Errorf("provider = %s, want azure", result.Provider)
	}
	if result.InstanceID != "vm-12345" {
		t.Errorf("instance_id = %s", result.InstanceID)
	}
	if result.Region != "eastus" {
		t.Errorf("region = %s", result.Region)
	}
	if result.PrivateIP != "10.0.0.4" {
		t.Errorf("private_ip = %s", result.PrivateIP)
	}
	if result.Credentials["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
}

func TestDetectProviderAWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest/api/token" && r.Method == "PUT" {
			w.Write([]byte("token"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	origBase := imdsBase
	setIMDSBase(srv.URL)
	defer setIMDSBase(origBase)

	p, err := DetectProvider()
	if err != nil {
		t.Fatalf("DetectProvider failed: %v", err)
	}
	if p != ProviderAWS {
		t.Errorf("detected = %s, want aws", p)
	}
}

func TestDetectProviderGCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/computeMetadata/v1/" && r.Header.Get("Metadata-Flavor") == "Google" {
			w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	origBase := imdsBase
	setIMDSBase(srv.URL)
	defer setIMDSBase(origBase)

	p, err := DetectProvider()
	if err != nil {
		t.Fatalf("DetectProvider failed: %v", err)
	}
	if p != ProviderGCP {
		t.Errorf("detected = %s, want gcp", p)
	}
}

func TestDetectProviderNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	origBase := imdsBase
	setIMDSBase(srv.URL)
	defer setIMDSBase(origBase)

	_, err := DetectProvider()
	if err == nil {
		t.Fatal("expected error when no provider detected")
	}
}

func TestMetadataResultJSON(t *testing.T) {
	result := &MetadataResult{
		Provider:   ProviderAWS,
		InstanceID: "i-123",
		Region:     "us-east-1",
		Credentials: map[string]string{
			"access_key_id": "AKIA...",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded MetadataResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.Provider != ProviderAWS {
		t.Errorf("decoded provider = %s", decoded.Provider)
	}
	if decoded.InstanceID != "i-123" {
		t.Errorf("decoded instance_id = %s", decoded.InstanceID)
	}
}
