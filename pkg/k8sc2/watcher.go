package k8sc2

import (
	"context"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

func (c *Controller) WatchChannel(ctx context.Context) <-chan Task {
	ch := make(chan Task, 16)

	go func() {
		defer close(ch)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			watcher, err := c.client.CoreV1().ConfigMaps(c.namespace).Watch(ctx, metav1.ListOptions{
				FieldSelector: "metadata.name=" + c.configMap,
			})
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}

			c.processEvents(ctx, watcher, ch)
			watcher.Stop()
		}
	}()

	return ch
}

func (c *Controller) processEvents(ctx context.Context, watcher watch.Interface, ch chan<- Task) {
	prefix := annotationPrefix + c.agentID + "-"
	seen := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			if event.Type != watch.Modified {
				continue
			}

			cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, c.configMap, metav1.GetOptions{})
			if err != nil {
				continue
			}

			for key, value := range cm.Annotations {
				if !strings.HasPrefix(key, prefix) {
					continue
				}
				taskID := strings.TrimPrefix(key, prefix)

				resultKey := resultPrefix + c.agentID + "-" + taskID
				if _, done := cm.Annotations[resultKey]; done {
					continue
				}

				if seen[taskID] {
					continue
				}
				seen[taskID] = true

				parts := strings.SplitN(value, "|", 2)
				task := Task{
					ID:        taskID,
					Command:   parts[0],
					Timestamp: time.Now(),
				}
				if len(parts) > 1 {
					task.Args = parseArgs(parts[1])
				}

				select {
				case ch <- task:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
