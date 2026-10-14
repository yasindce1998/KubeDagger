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
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestHotload_Validation(t *testing.T) {
	tests := []struct {
		name      string
		args      map[string]string
		wantError string
	}{
		{
			name:      "missing exec_b64",
			args:      map[string]string{"action": "exec"},
			wantError: "requires exec_b64",
		},
		{
			name:      "invalid base64",
			args:      map[string]string{"exec_b64": "!!!not-base64!!!"},
			wantError: "invalid base64",
		},
		{
			name:      "empty decoded payload",
			args:      map[string]string{"exec_b64": ""},
			wantError: "requires exec_b64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Hotload{}
			result, err := m.Execute(context.Background(), tt.args)
			if err == nil {
				t.Fatalf("expected error, got result: %+v", result)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("expected error containing %q, got %q", tt.wantError, err.Error())
			}
		})
	}
}

func TestHotload_InvalidTimeout(t *testing.T) {
	// Valid payload so validation reaches the timeout parse.
	encoded := base64.StdEncoding.EncodeToString([]byte("\x7fELF-placeholder"))

	m := &Hotload{}
	_, err := m.Execute(context.Background(), map[string]string{
		"exec_b64": encoded,
		"timeout":  "not-a-duration",
	})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), "invalid timeout") {
		t.Errorf("expected 'invalid timeout' error, got %q", err.Error())
	}
}

func TestHotload_ExecuteMemfd(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("memfd execution only supported on linux")
	}

	// Use grep so the test exercises the full in-memory exec path portably:
	// coreutils binaries on Ubuntu 26.04+ validate argv[0] against
	// /proc/self/exe and refuse to run from a memfd ("Security violation:
	// Requested utility ... /memfd: (deleted)") regardless of the argv[0]
	// value passed, while non-coreutils programs (grep, dash) execute fine.
	grepPath := "/bin/grep"
	if _, err := os.Stat(grepPath); err != nil {
		grepPath = "/usr/bin/grep"
		if _, err := os.Stat(grepPath); err != nil {
			t.Skip("no /bin/grep or /usr/bin/grep available for memfd exec test")
		}
	}
	bin, err := os.ReadFile(grepPath)
	if err != nil {
		t.Skipf("cannot read %s: %v", grepPath, err)
	}

	m := &Hotload{}
	result, err := m.Execute(context.Background(), map[string]string{
		"exec_b64": base64.StdEncoding.EncodeToString(bin),
		"argv0":    "memfd-test",
		"args_str": "--version",
		"timeout":  "30s",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s; result:\n%s", result.Error, result.Output)
	}
	if !strings.Contains(result.Output, "grep") {
		t.Errorf("expected captured output to contain 'grep', got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "exit code 0") {
		t.Errorf("expected exit code 0 in output, got:\n%s", result.Output)
	}
}

func TestHotload_Platform(t *testing.T) {
	m := &Hotload{}
	if m.Name() != "hotload" {
		t.Errorf("expected module name hotload, got %q", m.Name())
	}
	platforms := m.Platform()
	if len(platforms) != 1 || platforms[0] != "linux" {
		t.Errorf("expected linux-only platform, got %v", platforms)
	}
}
