package c2server

import (
	"testing"
)

func TestTaskQueue_EnqueueDequeue(t *testing.T) {
	q := NewTaskQueue()
	task := q.Enqueue("agent-1", TaskShell, map[string]string{"command": "whoami"})

	if task.ID == "" {
		t.Fatal("expected non-empty task ID")
	}
	if task.Status != StatusPending {
		t.Errorf("expected pending, got %s", task.Status)
	}

	dequeued := q.Dequeue("agent-1")
	if dequeued == nil {
		t.Fatal("expected task")
	}
	if dequeued.ID != task.ID {
		t.Errorf("expected same task ID")
	}
	if dequeued.Status != StatusDispatched {
		t.Errorf("expected dispatched, got %s", dequeued.Status)
	}
}

func TestTaskQueue_DequeueFIFO(t *testing.T) {
	q := NewTaskQueue()
	t1 := q.Enqueue("agent-1", TaskShell, map[string]string{"command": "first"})
	q.Enqueue("agent-1", TaskShell, map[string]string{"command": "second"})

	first := q.Dequeue("agent-1")
	if first.ID != t1.ID {
		t.Error("expected FIFO order")
	}
	if first.Payload["command"] != "first" {
		t.Errorf("expected 'first', got %q", first.Payload["command"])
	}
}

func TestTaskQueue_DequeueEmpty(t *testing.T) {
	q := NewTaskQueue()
	task := q.Dequeue("agent-1")
	if task != nil {
		t.Error("expected nil on empty queue")
	}
}

func TestTaskQueue_HasPending(t *testing.T) {
	q := NewTaskQueue()
	if q.HasPending("agent-1") {
		t.Error("expected no pending tasks")
	}

	q.Enqueue("agent-1", TaskShell, map[string]string{"command": "test"})
	if !q.HasPending("agent-1") {
		t.Error("expected pending tasks")
	}

	q.Dequeue("agent-1")
	if q.HasPending("agent-1") {
		t.Error("expected no pending after dequeue")
	}
}

func TestTaskQueue_Complete(t *testing.T) {
	q := NewTaskQueue()
	task := q.Enqueue("agent-1", TaskShell, map[string]string{"command": "id"})
	q.Dequeue("agent-1")

	q.Complete(task.ID, "uid=0(root)", "")

	completed, ok := q.Get(task.ID)
	if !ok {
		t.Fatal("expected to find task")
	}
	if completed.Status != StatusCompleted {
		t.Errorf("expected completed, got %s", completed.Status)
	}
	if completed.Output != "uid=0(root)" {
		t.Errorf("expected output, got %q", completed.Output)
	}
	if completed.FinishedAt == nil {
		t.Error("expected FinishedAt to be set")
	}
}

func TestTaskQueue_CompleteFailed(t *testing.T) {
	q := NewTaskQueue()
	task := q.Enqueue("agent-1", TaskShell, map[string]string{"command": "bad"})
	q.Dequeue("agent-1")

	q.Complete(task.ID, "", "exit status 1")

	completed, _ := q.Get(task.ID)
	if completed.Status != StatusFailed {
		t.Errorf("expected failed, got %s", completed.Status)
	}
	if completed.Error != "exit status 1" {
		t.Errorf("expected error string, got %q", completed.Error)
	}
}

func TestTaskQueue_ListForAgent(t *testing.T) {
	q := NewTaskQueue()
	q.Enqueue("agent-1", TaskShell, map[string]string{"command": "a"})
	q.Enqueue("agent-1", TaskShell, map[string]string{"command": "b"})
	q.Enqueue("agent-2", TaskShell, map[string]string{"command": "c"})

	list := q.ListForAgent("agent-1")
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

func TestTaskQueue_UniqueIDs(t *testing.T) {
	q := NewTaskQueue()
	ids := make(map[string]bool)
	for range 100 {
		task := q.Enqueue("agent-1", TaskShell, map[string]string{"command": "x"})
		if ids[task.ID] {
			t.Fatalf("duplicate ID: %s", task.ID)
		}
		ids[task.ID] = true
	}
}
