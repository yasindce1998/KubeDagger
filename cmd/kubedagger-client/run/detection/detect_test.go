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

package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "detections.md")

	if err := Generate("sa_token,polymorph,not_a_technique", out); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	md := string(data)

	if !strings.Contains(md, "# KubeDagger Detection Coverage Report") {
		t.Error("report missing title")
	}
	if !strings.Contains(md, "## sa_token — T1552.001") {
		t.Error("report missing sa_token section")
	}
	if !strings.Contains(md, "## Detection gaps") {
		t.Error("report missing gaps section for unknown technique")
	}
}

func TestGenerateAllDefault(t *testing.T) {
	out := filepath.Join(t.TempDir(), "all.md")

	if err := Generate("", out); err != nil {
		t.Fatalf("Generate default: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for _, technique := range []string{"sa_token", "escape", "webhook_deploy", "polymorph"} {
		if !strings.Contains(string(data), "## "+technique+" — ") {
			t.Errorf("default report missing technique %q", technique)
		}
	}
}

func TestParseTechniques(t *testing.T) {
	tests := []struct {
		name       string
		techniques string
		wantAll    bool
		want       []string
		wantErr    bool
	}{
		{name: "empty means all", techniques: "", wantAll: true},
		{name: "all keyword", techniques: "all", wantAll: true},
		{name: "single", techniques: " sa_token ", want: []string{"sa_token"}},
		{name: "comma separated with spaces", techniques: "sa_token, escape ,daemonset", want: []string{"sa_token", "escape", "daemonset"}},
		{name: "only commas", techniques: " , ,", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTechniques(tt.techniques)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTechniques(%q) err = %v, wantErr %v", tt.techniques, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantAll {
				if len(got) == 0 {
					t.Errorf("parseTechniques(%q) returned empty list, want full catalog", tt.techniques)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseTechniques(%q) = %v, want %v", tt.techniques, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("parseTechniques(%q)[%d] = %q, want %q", tt.techniques, i, got[i], tt.want[i])
				}
			}
		})
	}
}
