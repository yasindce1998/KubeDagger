package agent

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

func TestExecShell_Echo(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo hello"
	} else {
		cmd = "echo hello"
	}

	task := &c2server.TaskResponse{
		Type:    c2server.TaskShell,
		Payload: map[string]string{"command": cmd},
	}

	output, err := e.Execute(ctx, task)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(output, "hello") {
		t.Errorf("expected 'hello' in output, got %q", output)
	}
}

func TestExecShell_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("timeout test unreliable on Windows CI")
	}

	e := NewExecutor()
	ctx := context.Background()

	task := &c2server.TaskResponse{
		Type:    c2server.TaskShell,
		Payload: map[string]string{"command": "sleep 10", "timeout": "100ms"},
	}

	_, err := e.Execute(ctx, task)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected 'timed out' in error, got %q", err.Error())
	}
}

func TestExecShell_MissingCommand(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	task := &c2server.TaskResponse{
		Type:    c2server.TaskShell,
		Payload: map[string]string{},
	}

	_, err := e.Execute(ctx, task)
	if err == nil {
		t.Fatal("expected error for missing command")
	}
	if !strings.Contains(err.Error(), "missing command") {
		t.Errorf("expected 'missing command' in error, got %q", err.Error())
	}
}

func TestExecShell_OutputCap(t *testing.T) {
	e := NewExecutor()
	e.MaxOutput = 20
	ctx := context.Background()

	long := strings.Repeat("X", 100)
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo " + long
	} else {
		cmd = "echo " + long
	}

	task := &c2server.TaskResponse{
		Type:    c2server.TaskShell,
		Payload: map[string]string{"command": cmd},
	}

	output, _ := e.Execute(ctx, task)
	if !strings.HasSuffix(output, "[TRUNCATED]") {
		t.Errorf("expected truncation marker, got output (%d chars): %q", len(output), output)
	}
}

func TestExecModule_NotFound(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	task := &c2server.TaskResponse{
		Type:    c2server.TaskModule,
		Payload: map[string]string{"name": "nonexistent_module"},
	}

	_, err := e.Execute(ctx, task)
	if err == nil {
		t.Fatal("expected error for unknown module")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got %q", err.Error())
	}
}

func TestExecModule_MissingName(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	task := &c2server.TaskResponse{
		Type:    c2server.TaskModule,
		Payload: map[string]string{},
	}

	_, err := e.Execute(ctx, task)
	if err == nil {
		t.Fatal("expected error for missing module name")
	}
	if !strings.Contains(err.Error(), "missing module name") {
		t.Errorf("expected 'missing module name', got %q", err.Error())
	}
}

func TestExecConfig(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	task := &c2server.TaskResponse{
		Type:    c2server.TaskConfig,
		Payload: map[string]string{"key": "value"},
	}

	output, err := e.Execute(ctx, task)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != "config updated" {
		t.Errorf("expected 'config updated', got %q", output)
	}
}

func TestExecUnsupportedType(t *testing.T) {
	e := NewExecutor()
	ctx := context.Background()

	task := &c2server.TaskResponse{
		Type:    "unknown_type",
		Payload: map[string]string{},
	}

	_, err := e.Execute(ctx, task)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported task type") {
		t.Errorf("expected 'unsupported task type', got %q", err.Error())
	}
}

func TestJitteredSleep_Range(t *testing.T) {
	a := &Agent{
		cfg: Config{BeaconJitter: 0.2},
	}

	base := 10 * time.Second
	minExpected := base - time.Duration(float64(base)*0.2)
	maxExpected := base + time.Duration(float64(base)*0.2)

	for range 100 {
		d := a.jitteredSleep(base)
		if d < minExpected || d > maxExpected {
			t.Errorf("jittered duration %s outside [%s, %s]", d, minExpected, maxExpected)
		}
	}
}

func TestAgent_Stop(t *testing.T) {
	cfg := Config{
		ServerURL:    "https://127.0.0.1:9999",
		AgentID:      "test-stop",
		BeaconJitter: 0.1,
		MaxRetries:   1,
	}
	a := New(cfg, nil)
	a.Stop()

	select {
	case <-a.stop:
	default:
		t.Error("expected stop channel to be closed")
	}
}
