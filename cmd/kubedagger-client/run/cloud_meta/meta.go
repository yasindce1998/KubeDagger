package cloud_meta

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var imdsBase = "http://169.254.169.254"

func setIMDSBase(base string) {
	imdsBase = base
}

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

type MetadataResult struct {
	Provider    Provider               `json:"provider"`
	InstanceID  string                 `json:"instance_id,omitempty"`
	Region      string                 `json:"region,omitempty"`
	Zone        string                 `json:"zone,omitempty"`
	Hostname    string                 `json:"hostname,omitempty"`
	PrivateIP   string                 `json:"private_ip,omitempty"`
	PublicIP    string                 `json:"public_ip,omitempty"`
	Credentials map[string]string      `json:"credentials,omitempty"`
	UserData    string                 `json:"user_data,omitempty"`
	Raw         map[string]any `json:"raw,omitempty"`
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Second}
}

func DetectProvider() (Provider, error) {
	client := newHTTPClient()

	// Try AWS IMDSv2 token first
	req, _ := http.NewRequest("PUT", imdsBase+"/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return ProviderAWS, nil
		}
	}

	// Try AWS IMDSv1
	if resp, err := client.Get(imdsBase + "/latest/meta-data/"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return ProviderAWS, nil
		}
	}

	// Try GCP
	req, _ = http.NewRequest("GET", imdsBase+"/computeMetadata/v1/", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return ProviderGCP, nil
		}
	}

	// Try Azure
	req, _ = http.NewRequest("GET", imdsBase+"/metadata/instance?api-version=2021-02-01", nil)
	req.Header.Set("Metadata", "true")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return ProviderAzure, nil
		}
	}

	return "", fmt.Errorf("no cloud metadata service detected")
}

func FetchMetadata(provider string) (*MetadataResult, error) {
	var p Provider
	if provider == "" || provider == "auto" {
		detected, err := DetectProvider()
		if err != nil {
			return nil, err
		}
		p = detected
	} else {
		p = Provider(provider)
	}

	switch p {
	case ProviderAWS:
		return fetchAWS()
	case ProviderGCP:
		return fetchGCP()
	case ProviderAzure:
		return fetchAzure()
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func fetchAWS() (*MetadataResult, error) {
	client := newHTTPClient()
	result := &MetadataResult{Provider: ProviderAWS, Credentials: make(map[string]string)}

	// Get IMDSv2 token
	var token string
	req, _ := http.NewRequest("PUT", imdsBase+"/latest/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	if resp, err := client.Do(req); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 {
			token = string(body)
		}
	}

	get := func(path string) string {
		req, _ := http.NewRequest("GET", imdsBase+path, nil)
		if token != "" {
			req.Header.Set("X-aws-ec2-metadata-token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(body))
	}

	result.InstanceID = get("/latest/meta-data/instance-id")
	result.Region = get("/latest/meta-data/placement/region")
	result.Zone = get("/latest/meta-data/placement/availability-zone")
	result.Hostname = get("/latest/meta-data/hostname")
	result.PrivateIP = get("/latest/meta-data/local-ipv4")
	result.PublicIP = get("/latest/meta-data/public-ipv4")
	result.UserData = get("/latest/user-data")

	// Get IAM role credentials
	roleName := get("/latest/meta-data/iam/security-credentials/")
	if roleName != "" {
		credsJSON := get("/latest/meta-data/iam/security-credentials/" + roleName)
		if credsJSON != "" {
			var creds map[string]any
			if json.Unmarshal([]byte(credsJSON), &creds) == nil {
				result.Credentials["role"] = roleName
				if v, ok := creds["AccessKeyId"].(string); ok {
					result.Credentials["access_key_id"] = v
				}
				if v, ok := creds["SecretAccessKey"].(string); ok {
					result.Credentials["secret_access_key"] = v
				}
				if v, ok := creds["Token"].(string); ok {
					result.Credentials["session_token"] = v
				}
				if v, ok := creds["Expiration"].(string); ok {
					result.Credentials["expiration"] = v
				}
			}
		}
	}

	return result, nil
}

func fetchGCP() (*MetadataResult, error) {
	client := newHTTPClient()
	result := &MetadataResult{Provider: ProviderGCP, Credentials: make(map[string]string)}

	get := func(path string) string {
		req, _ := http.NewRequest("GET", imdsBase+path, nil)
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(body))
	}

	result.InstanceID = get("/computeMetadata/v1/instance/id")
	result.Zone = get("/computeMetadata/v1/instance/zone")
	result.Hostname = get("/computeMetadata/v1/instance/hostname")
	result.PrivateIP = get("/computeMetadata/v1/instance/network-interfaces/0/ip")
	result.PublicIP = get("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")

	// Extract region from zone (projects/NUM/zones/us-central1-a -> us-central1)
	if result.Zone != "" {
		parts := strings.Split(result.Zone, "/")
		zone := parts[len(parts)-1]
		if idx := strings.LastIndex(zone, "-"); idx > 0 {
			result.Region = zone[:idx]
		}
	}

	// Get service account token
	tokenJSON := get("/computeMetadata/v1/instance/service-accounts/default/token")
	if tokenJSON != "" {
		var tok map[string]any
		if json.Unmarshal([]byte(tokenJSON), &tok) == nil {
			if v, ok := tok["access_token"].(string); ok {
				result.Credentials["access_token"] = v
			}
			if v, ok := tok["token_type"].(string); ok {
				result.Credentials["token_type"] = v
			}
		}
	}

	email := get("/computeMetadata/v1/instance/service-accounts/default/email")
	if email != "" {
		result.Credentials["service_account"] = email
	}

	scopes := get("/computeMetadata/v1/instance/service-accounts/default/scopes")
	if scopes != "" {
		result.Credentials["scopes"] = scopes
	}

	return result, nil
}

func fetchAzure() (*MetadataResult, error) {
	client := newHTTPClient()
	result := &MetadataResult{Provider: ProviderAzure, Credentials: make(map[string]string)}

	get := func(path string) string {
		req, _ := http.NewRequest("GET", imdsBase+path, nil)
		req.Header.Set("Metadata", "true")
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(body))
	}

	instanceJSON := get("/metadata/instance?api-version=2021-02-01")
	if instanceJSON != "" {
		var instance map[string]any
		if json.Unmarshal([]byte(instanceJSON), &instance) == nil {
			result.Raw = instance
			if compute, ok := instance["compute"].(map[string]any); ok {
				if v, ok := compute["vmId"].(string); ok {
					result.InstanceID = v
				}
				if v, ok := compute["location"].(string); ok {
					result.Region = v
				}
				if v, ok := compute["name"].(string); ok {
					result.Hostname = v
				}
			}
			if network, ok := instance["network"].(map[string]any); ok {
				if ifaces, ok := network["interface"].([]any); ok && len(ifaces) > 0 {
					if iface, ok := ifaces[0].(map[string]any); ok {
						if ipv4, ok := iface["ipv4"].(map[string]any); ok {
							if addrs, ok := ipv4["ipAddress"].([]any); ok && len(addrs) > 0 {
								if addr, ok := addrs[0].(map[string]any); ok {
									if v, ok := addr["privateIpAddress"].(string); ok {
										result.PrivateIP = v
									}
									if v, ok := addr["publicIpAddress"].(string); ok {
										result.PublicIP = v
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Get managed identity token
	tokenJSON := get("/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/")
	if tokenJSON != "" {
		var tok map[string]any
		if json.Unmarshal([]byte(tokenJSON), &tok) == nil {
			if v, ok := tok["access_token"].(string); ok {
				result.Credentials["access_token"] = v
			}
			if v, ok := tok["token_type"].(string); ok {
				result.Credentials["token_type"] = v
			}
			if v, ok := tok["resource"].(string); ok {
				result.Credentials["resource"] = v
			}
		}
	}

	return result, nil
}

func PrintResult(result *MetadataResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
