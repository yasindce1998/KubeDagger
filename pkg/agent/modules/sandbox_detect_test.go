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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSandboxDetect_Execute(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, root string)
		wantFind    []string
		notWantFind []string
	}{
		{
			name:  "gVisor",
			setup: writeProcFiles(map[string]string{"/proc/version": "Linux version 5.10 (gVisor)"}),
			wantFind: []string{
				"gVisor detected",
				"eBPF loading unavailable",
			},
		},
		{
			name:  "gVisor mounts hint only",
			setup: writeProcFiles(map[string]string{"/proc/mounts": "runsc / gvisorfuse"}),
			wantFind: []string{
				"gVisor hint in /proc/mounts",
			},
		},
		{
			name: "Kata Containers",
			setup: func(t *testing.T, root string) {
				writeDMI(t, root, map[string]string{"product_name": "Kata Containers"})
			},
			wantFind: []string{"Kata Containers detected"},
		},
		{
			name: "Kata via product_version",
			setup: func(t *testing.T, root string) {
				writeDMI(t, root, map[string]string{"product_version": "Kata 2.x"})
			},
			wantFind: []string{"Kata Containers detected"},
		},
		{
			name: "Firecracker",
			setup: func(t *testing.T, root string) {
				writeDMI(t, root, map[string]string{"product_name": "Firecracker MicroVM"})
			},
			wantFind: []string{"Firecracker microVM detected"},
		},
		{
			name:     "WSL",
			setup:    writeProcFiles(map[string]string{"/proc/version": "Linux version ...-microsoft-standard-WSL2"}),
			wantFind: []string{"WSL detected"},
		},
		{
			name:     "Docker via .dockerenv",
			setup:    writeProcFiles(map[string]string{"/.dockerenv": ""}),
			wantFind: []string{"container detected (.dockerenv)"},
		},
		{
			name:     "Kubernetes via cgroup",
			setup:    writeProcFiles(map[string]string{"/proc/1/cgroup": "0::/kubepods.slice/..."}),
			wantFind: []string{"container detected (kubepods in /proc/1/cgroup)"},
		},
		{
			name: "VMware VM",
			setup: func(t *testing.T, root string) {
				writeDMI(t, root, map[string]string{"sys_vendor": "VMware, Inc."})
			},
			wantFind: []string{"VM hint (DMI sys_vendor: VMware)"},
		},
		{
			name: "Hyper-V VM",
			setup: func(t *testing.T, root string) {
				writeDMI(t, root, map[string]string{"sys_vendor": "Microsoft Corporation"})
			},
			wantFind: []string{"VM hint (DMI sys_vendor: Microsoft Corporation)"},
		},
		{
			name:        "clean environment",
			setup:       writeProcFiles(nil),
			wantFind:    []string{"no sandbox, container, or VM indicators detected"},
			notWantFind: []string{"gVisor", "Kata", "Firecracker", "WSL", "container detected", "VM hint"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setup(t, root)

			m := &SandboxDetect{}
			result, err := m.Execute(context.Background(), map[string]string{"root": root})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Success {
				t.Fatalf("expected success, got error: %s", result.Error)
			}

			for _, want := range tt.wantFind {
				if !strings.Contains(result.Output, want) {
					t.Errorf("expected output to contain %q, got:\n%s", want, result.Output)
				}
			}
			for _, notWant := range tt.notWantFind {
				if strings.Contains(result.Output, notWant) {
					t.Errorf("expected output to NOT contain %q, got:\n%s", notWant, result.Output)
				}
			}
		})
	}
}

func TestSandboxDetect_Platforms(t *testing.T) {
	m := &SandboxDetect{}
	if m.Name() != "sandbox_detect" {
		t.Errorf("expected module name sandbox_detect, got %q", m.Name())
	}
	platforms := m.Platform()
	if len(platforms) != 3 {
		t.Errorf("expected 3 platforms, got %v", platforms)
	}
}

// writeProcFiles returns a setup func that writes files relative to a fake
// filesystem root (used as args["root"] for the module).
func writeProcFiles(files map[string]string) func(t *testing.T, root string) {
	return func(t *testing.T, root string) {
		for path, content := range files {
			full := filepath.Join(root, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatalf("write %s: %v", full, err)
			}
		}
	}
}

// writeDMI writes files under the fake DMI id directory.
func writeDMI(t *testing.T, root string, files map[string]string) {
	t.Helper()
	writeProcFiles(nil)(t, root) // ensure root exists
	for name, content := range files {
		full := filepath.Join(root, "/sys/devices/virtual/dmi/id", name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}
