package cloudevasion

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var knativeServiceGVR = schema.GroupVersionResource{
	Group: "serving.knative.dev", Version: "v1", Resource: "services",
}

var knativeRevisionGVR = schema.GroupVersionResource{
	Group: "serving.knative.dev", Version: "v1", Resource: "revisions",
}

func detectKnative(ctx context.Context, client kubernetes.Interface) []DetectionSystem {
	namespaces := []string{"knative-serving", "knative-eventing"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(pods.Items) > 0 {
			return []DetectionSystem{{
				Name:      "knative",
				Detected:  true,
				Namespace: ns,
				Details:   fmt.Sprintf("%d knative pods in %s", len(pods.Items), ns),
			}}
		}
	}

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		LabelSelector: "app=queue-proxy",
	})
	if err == nil && len(pods.Items) > 0 {
		return []DetectionSystem{{
			Name:      "knative",
			Detected:  true,
			Namespace: pods.Items[0].Namespace,
			Details:   fmt.Sprintf("queue-proxy sidecars detected (%d pods)", len(pods.Items)),
		}}
	}

	return nil
}

// ExploitKnative executes the specified Knative serverless exploitation technique.
func ExploitKnative(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface, technique string) (*EvasionResult, error) {
	switch technique {
	case "enumerate":
		return knativeEnumerate(ctx, client, dynClient)
	case "queue_proxy":
		return knativeQueueProxy(ctx, client)
	case "autoscaler_abuse":
		return knativeAutoscalerAbuse(ctx, client)
	case "revision_inject":
		return knativeRevisionInject(ctx, dynClient)
	default:
		return knativeEnumerate(ctx, client, dynClient)
	}
}

func knativeEnumerate(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Knative Serverless Enumeration:\n\n")

	found := false

	services, err := dynClient.Resource(knativeServiceGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(services.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  Knative Services (%d):\n", len(services.Items))
		for _, svc := range services.Items {
			status, _ := svc.Object["status"].(map[string]any)
			url, _ := status["url"].(string)
			fmt.Fprintf(&sb, "    %s/%s → %s\n", svc.GetNamespace(), svc.GetName(), url)
		}
		sb.WriteString("\n")
	}

	revisions, err := dynClient.Resource(knativeRevisionGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err == nil && len(revisions.Items) > 0 {
		found = true
		fmt.Fprintf(&sb, "  Revisions (%d):\n", len(revisions.Items))
		for _, rev := range revisions.Items {
			spec, _ := rev.Object["spec"].(map[string]any)
			containers, _ := spec["containers"].([]any)
			image := ""
			if len(containers) > 0 {
				c, _ := containers[0].(map[string]any)
				image, _ = c["image"].(string)
			}
			fmt.Fprintf(&sb, "    %s/%s image=%s\n", rev.GetNamespace(), rev.GetName(), image)
		}
		sb.WriteString("\n")
	}

	namespaces := []string{"knative-serving", "knative-eventing"}
	for _, ns := range namespaces {
		pods, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err == nil && len(pods.Items) > 0 {
			fmt.Fprintf(&sb, "  %s pods:\n", ns)
			for _, pod := range pods.Items {
				fmt.Fprintf(&sb, "    %s (phase=%s)\n", pod.Name, pod.Status.Phase)
			}
			sb.WriteString("\n")
		}
	}

	if !found {
		sb.WriteString("  No Knative resources detected\n")
	}

	return &EvasionResult{
		Technique: "enumerate",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func knativeQueueProxy(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Knative Queue-Proxy Interception:\n\n")

	sb.WriteString("  Queue-proxy is a sidecar injected into every Knative Service pod.\n")
	sb.WriteString("  It proxies all inbound traffic — intercepting it gives full request visibility.\n\n")

	pods, err := client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 100})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list pods: %v\n", err)
		return &EvasionResult{Technique: "queue_proxy", Success: false, Output: sb.String()}, nil
	}

	queueProxyPods := 0
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Name == "queue-proxy" {
				queueProxyPods++
				if queueProxyPods <= 5 {
					fmt.Fprintf(&sb, "  [TARGET] %s/%s\n", pod.Namespace, pod.Name)
					for _, port := range container.Ports {
						fmt.Fprintf(&sb, "    Port: %s %d\n", port.Name, port.ContainerPort)
					}
					for _, env := range container.Env {
						if strings.Contains(env.Name, "PORT") || strings.Contains(env.Name, "METRICS") {
							fmt.Fprintf(&sb, "    Env: %s=%s\n", env.Name, env.Value)
						}
					}
				}
			}
		}
	}

	if queueProxyPods > 5 {
		fmt.Fprintf(&sb, "  ... %d total pods with queue-proxy\n", queueProxyPods)
	}

	configMaps, err := client.CoreV1().ConfigMaps("knative-serving").List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, cm := range configMaps.Items {
			if cm.Name == "config-observability" || cm.Name == "config-network" {
				fmt.Fprintf(&sb, "\n  ConfigMap: %s\n", cm.Name)
				for key, val := range cm.Data {
					if len(val) < 80 {
						fmt.Fprintf(&sb, "    %s: %s\n", key, val)
					}
				}
			}
		}
	}

	sb.WriteString("\n  Queue-proxy attack vectors:\n")
	sb.WriteString("    1. Access queue-proxy metrics port (9090) for request data\n")
	sb.WriteString("    2. Admin port (9091) exposes profiling and healthz\n")
	sb.WriteString("    3. Modify queue-proxy image in config-deployment ConfigMap\n")
	sb.WriteString("    4. Inject env vars via container spec to redirect traffic\n")
	sb.WriteString("    5. Queue-proxy sees all headers including auth tokens\n")

	return &EvasionResult{
		Technique: "queue_proxy",
		Success:   queueProxyPods > 0,
		Output:    sb.String(),
	}, nil
}

func knativeAutoscalerAbuse(ctx context.Context, client kubernetes.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Knative Autoscaler Abuse:\n\n")

	sb.WriteString("  Knative autoscaler scales pods based on request concurrency/RPS.\n")
	sb.WriteString("  Manipulating autoscaler config enables resource exhaustion attacks.\n\n")

	configMaps, err := client.CoreV1().ConfigMaps("knative-serving").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list ConfigMaps in knative-serving: %v\n", err)
		return &EvasionResult{Technique: "autoscaler_abuse", Success: false, Output: sb.String()}, nil
	}

	found := false
	for _, cm := range configMaps.Items {
		if cm.Name == "config-autoscaler" {
			found = true
			fmt.Fprintf(&sb, "  config-autoscaler:\n")
			for key, val := range cm.Data {
				fmt.Fprintf(&sb, "    %s: %s\n", key, val)
			}
		}
		if cm.Name == "config-defaults" {
			fmt.Fprintf(&sb, "\n  config-defaults:\n")
			for key, val := range cm.Data {
				if strings.Contains(key, "scale") || strings.Contains(key, "concurrency") || strings.Contains(key, "container") {
					fmt.Fprintf(&sb, "    %s: %s\n", key, val)
				}
			}
		}
	}

	pods, err := client.CoreV1().Pods("knative-serving").List(ctx, metav1.ListOptions{
		LabelSelector: "app=autoscaler",
	})
	if err == nil && len(pods.Items) > 0 {
		for _, pod := range pods.Items {
			fmt.Fprintf(&sb, "\n  Autoscaler pod: %s (phase=%s)\n", pod.Name, pod.Status.Phase)
		}
	}

	sb.WriteString("\n  Autoscaler abuse techniques:\n")
	sb.WriteString("    1. Set max-scale-limit to 1000+ → flood with requests → resource exhaustion\n")
	sb.WriteString("    2. Set scale-to-zero-grace-period to 0 → constant cold starts (DoS)\n")
	sb.WriteString("    3. Modify container-concurrency to 1 → every request spawns a pod\n")
	sb.WriteString("    4. Set initial-scale very high → immediate resource consumption on deploy\n")
	sb.WriteString("    5. Disable scale-to-zero → pods persist, consuming resources indefinitely\n")
	sb.WriteString("    6. Crash autoscaler pod → services cannot scale, eventual OOM\n")

	return &EvasionResult{
		Technique: "autoscaler_abuse",
		Success:   found,
		Output:    sb.String(),
	}, nil
}

func knativeRevisionInject(ctx context.Context, dynClient dynamic.Interface) (*EvasionResult, error) {
	var sb strings.Builder
	sb.WriteString("Knative Revision Template Injection:\n\n")

	sb.WriteString("  Knative Service spec.template defines the container for new Revisions.\n")
	sb.WriteString("  Modifying the template changes what code runs when the service is invoked.\n\n")

	services, err := dynClient.Resource(knativeServiceGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(&sb, "  Cannot list Knative Services: %v\n", err)
		return &EvasionResult{Technique: "revision_inject", Success: false, Output: sb.String()}, nil
	}

	fmt.Fprintf(&sb, "  Knative Services (%d):\n", len(services.Items))
	for _, svc := range services.Items {
		spec, _ := svc.Object["spec"].(map[string]any)
		template, _ := spec["template"].(map[string]any)
		templateSpec, _ := template["spec"].(map[string]any)
		containers, _ := templateSpec["containers"].([]any)

		fmt.Fprintf(&sb, "    %s/%s\n", svc.GetNamespace(), svc.GetName())
		for _, c := range containers {
			cMap, _ := c.(map[string]any)
			image, _ := cMap["image"].(string)
			fmt.Fprintf(&sb, "      Container: image=%s\n", image)
		}

		status, _ := svc.Object["status"].(map[string]any)
		if traffic, ok := status["traffic"].([]any); ok {
			for _, t := range traffic {
				tMap, _ := t.(map[string]any)
				revName, _ := tMap["revisionName"].(string)
				percent, _ := tMap["percent"].(float64)
				fmt.Fprintf(&sb, "      Traffic: %s (%d%%)\n", revName, int(percent))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("  Revision injection techniques:\n")
	sb.WriteString("    1. Modify service template image → new revision with attacker code\n")
	sb.WriteString("    2. Add initContainer to template → runs before user container\n")
	sb.WriteString("    3. Add env vars with malicious config/credentials\n")
	sb.WriteString("    4. Modify command/args to prepend data exfiltration\n")
	sb.WriteString("    5. Add volume mounts to access node filesystem\n")
	sb.WriteString("    6. Traffic split: route small % to attacker revision for stealth\n")

	return &EvasionResult{
		Technique: "revision_inject",
		Success:   len(services.Items) > 0,
		Output:    sb.String(),
	}, nil
}
