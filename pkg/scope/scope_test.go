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

package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeScopeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write scope file: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := writeScopeFile(t, `
namespaces:
  - default
  - kube-system
domains:
  - ".example.com"
  - "api.internal"
cidrs:
  - "10.0.0.0/8"
  - "192.168.1.0/24"
`)

	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Namespaces) != 2 || s.Namespaces[0] != "default" || s.Namespaces[1] != "kube-system" {
		t.Errorf("unexpected namespaces: %v", s.Namespaces)
	}
	if len(s.Domains) != 2 || s.Domains[0] != ".example.com" || s.Domains[1] != "api.internal" {
		t.Errorf("unexpected domains: %v", s.Domains)
	}
	if len(s.CIDRs) != 2 || s.CIDRs[0] != "10.0.0.0/8" || s.CIDRs[1] != "192.168.1.0/24" {
		t.Errorf("unexpected cidrs: %v", s.CIDRs)
	}
	if s.Empty() {
		t.Error("expected non-empty scope")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if s != nil {
		t.Errorf("expected nil scope, got %+v", s)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeScopeFile(t, "namespaces: [unclosed")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestLoad_InvalidCIDR(t *testing.T) {
	path := writeScopeFile(t, `
cidrs:
  - "10.0.0.0/8"
  - "not-a-cidr"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid cidr")
	}
	if !strings.Contains(err.Error(), "not-a-cidr") {
		t.Errorf("expected error to mention bad cidr, got: %v", err)
	}
}

func TestLoad_WildcardCIDR(t *testing.T) {
	path := writeScopeFile(t, `
cidrs:
  - "*"
`)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !s.AllowsIP("203.0.113.7") {
		t.Error("expected wildcard cidr to allow any ip")
	}
}

func TestEmpty(t *testing.T) {
	tests := []struct {
		name  string
		scope *Scope
		want  bool
	}{
		{"nil scope", nil, true},
		{"zero scope", &Scope{}, true},
		{"namespaces only", &Scope{Namespaces: []string{"default"}}, false},
		{"domains only", &Scope{Domains: []string{".example.com"}}, false},
		{"cidrs only", &Scope{CIDRs: []string{"10.0.0.0/8"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.Empty(); got != tt.want {
				t.Errorf("Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllowsNamespace(t *testing.T) {
	limited := &Scope{Namespaces: []string{"default", "kube-system"}}
	wildcard := &Scope{Namespaces: []string{"*"}}

	tests := []struct {
		name  string
		scope *Scope
		ns    string
		want  bool
	}{
		{"allowed", limited, "default", true},
		{"allowed second", limited, "kube-system", true},
		{"case insensitive", limited, "DEFAULT", true},
		{"denied", limited, "prod", false},
		{"wildcard", wildcard, "anything", true},
		{"no restriction", &Scope{Domains: []string{".example.com"}}, "prod", true},
		{"nil scope", nil, "prod", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.AllowsNamespace(tt.ns); got != tt.want {
				t.Errorf("AllowsNamespace(%q) = %v, want %v", tt.ns, got, tt.want)
			}
		})
	}
}

func TestAllowsHost(t *testing.T) {
	limited := &Scope{Domains: []string{".example.com", "api.internal"}}
	wildcard := &Scope{Domains: []string{"*"}}

	tests := []struct {
		name  string
		scope *Scope
		host  string
		want  bool
	}{
		{"exact subdomain", limited, "api.example.com", true},
		{"deep subdomain", limited, "a.b.example.com", true},
		{"apex of dot entry", limited, "example.com", true},
		{"plain exact", limited, "api.internal", true},
		{"plain no substring", limited, "internal", false},
		{"denied", limited, "evil.com", false},
		{"dot boundary respected", limited, "notexample.com", false},
		{"port stripped", limited, "api.example.com:8443", true},
		{"case insensitive", limited, "API.Example.COM", true},
		{"wildcard", wildcard, "anything.evil.net", true},
		{"no restriction", &Scope{Namespaces: []string{"default"}}, "evil.com", true},
		{"nil scope", nil, "evil.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.AllowsHost(tt.host); got != tt.want {
				t.Errorf("AllowsHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestAllowsIP(t *testing.T) {
	limited := &Scope{CIDRs: []string{"10.0.0.0/8", "192.168.1.0/24"}}
	wildcard := &Scope{CIDRs: []string{"*"}}

	tests := []struct {
		name  string
		scope *Scope
		ip    string
		want  bool
	}{
		{"inside first cidr", limited, "10.1.2.3", true},
		{"inside second cidr", limited, "192.168.1.55", true},
		{"outside second cidr", limited, "192.168.2.1", false},
		{"outside all", limited, "8.8.8.8", false},
		{"ipv6 denied", limited, "::1", false},
		{"unparseable denied", limited, "not-an-ip", false},
		{"port stripped", limited, "10.1.2.3:8080", true},
		{"wildcard", wildcard, "203.0.113.7", true},
		{"no restriction", &Scope{Namespaces: []string{"default"}}, "8.8.8.8", true},
		{"nil scope", nil, "8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.AllowsIP(tt.ip); got != tt.want {
				t.Errorf("AllowsIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCheckTask(t *testing.T) {
	limited := &Scope{
		Namespaces: []string{"default"},
		Domains:    []string{".example.com"},
		CIDRs:      []string{"10.0.0.0/8"},
	}

	tests := []struct {
		name       string
		scope      *Scope
		taskType   string
		payload    map[string]string
		wantErr    bool
		wantSubstr []string
	}{
		{
			name:     "all targets allowed",
			scope:    limited,
			taskType: "shell",
			payload: map[string]string{
				"namespace": "default",
				"ns":        "default",
				"host":      "api.example.com",
				"target":    "www.example.com",
				"ip":        "10.1.1.1",
				"url":       "https://api.example.com/v1",
			},
		},
		{
			name:     "url with allowed ip host",
			scope:    limited,
			taskType: "shell",
			payload:  map[string]string{"url": "http://10.2.3.4/path"},
		},
		{
			name:     "unrelated keys ignored",
			scope:    limited,
			taskType: "shell",
			payload:  map[string]string{"command": "id", "name": "recon"},
		},
		{
			name:     "empty values ignored",
			scope:    limited,
			taskType: "shell",
			payload:  map[string]string{"namespace": "", "host": "  "},
		},
		{
			name:       "namespace alias denied",
			scope:      limited,
			taskType:   "shell",
			payload:    map[string]string{"ns": "prod"},
			wantErr:    true,
			wantSubstr: []string{`namespace "prod" not in allowed namespaces`},
		},
		{
			name:       "url ip denied",
			scope:      limited,
			taskType:   "shell",
			payload:    map[string]string{"url": "http://8.8.8.8/x"},
			wantErr:    true,
			wantSubstr: []string{`url "http://8.8.8.8/x" ip "8.8.8.8" not in allowed cidrs`},
		},
		{
			name:       "url host denied",
			scope:      limited,
			taskType:   "shell",
			payload:    map[string]string{"url": "https://evil.com/x"},
			wantErr:    true,
			wantSubstr: []string{`url "https://evil.com/x" host "evil.com" not in allowed domains`},
		},
		{
			name:     "multiple violations collected",
			scope:    limited,
			taskType: "shell",
			payload: map[string]string{
				"namespace": "prod",
				"host":      "evil.com",
				"ip":        "8.8.8.8",
			},
			wantErr: true,
			wantSubstr: []string{
				`namespace "prod" not in allowed namespaces`,
				`host "evil.com" not in allowed domains`,
				`ip "8.8.8.8" not in allowed cidrs`,
			},
		},
		{
			name:     "nil scope allows everything",
			scope:    nil,
			taskType: "shell",
			payload:  map[string]string{"namespace": "prod", "host": "evil.com", "ip": "8.8.8.8"},
		},
		{
			name:     "empty scope allows everything",
			scope:    &Scope{},
			taskType: "shell",
			payload:  map[string]string{"namespace": "prod", "host": "evil.com"},
		},
		{
			name:     "nil payload",
			scope:    limited,
			taskType: "shell",
		},
		{
			name:     "task type included in error",
			scope:    limited,
			taskType: "shell",
			payload: map[string]string{
				"namespace": "prod",
				"host":      "evil.com",
			},
			wantErr:    true,
			wantSubstr: []string{"shell:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scope.CheckTask(tt.taskType, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				for _, substr := range tt.wantSubstr {
					if !strings.Contains(err.Error(), substr) {
						t.Errorf("error %q does not contain %q", err.Error(), substr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
