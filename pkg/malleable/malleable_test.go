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

package malleable

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeProfileFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write profile file: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := writeProfileFile(t, `
name: lab
sleep_base_seconds: 15
jitter_pct: 40
user_agents:
  - "UA-One"
  - "UA-Two"
headers:
  X-Custom: value
`)

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Name != "lab" {
		t.Errorf("expected name lab, got %q", p.Name)
	}
	if p.SleepBaseSeconds != 15 {
		t.Errorf("expected sleep base 15, got %d", p.SleepBaseSeconds)
	}
	if p.JitterPct != 40 {
		t.Errorf("expected jitter 40, got %d", p.JitterPct)
	}
	if len(p.UserAgents) != 2 {
		t.Errorf("expected 2 user agents, got %d", len(p.UserAgents))
	}
	if p.Headers["X-Custom"] != "value" {
		t.Errorf("expected header X-Custom=value, got %v", p.Headers)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	p, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if p != nil {
		t.Errorf("expected nil profile, got %+v", p)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeProfileFile(t, "name: [unclosed")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestLoad_InvalidProfile(t *testing.T) {
	path := writeProfileFile(t, `
name: bad
sleep_base_seconds: 30
jitter_pct: 150
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}
	if !strings.Contains(err.Error(), "jitter_pct") {
		t.Errorf("expected jitter error, got: %v", err)
	}
}

func TestDefault(t *testing.T) {
	p := Default()
	if p.Name != "default" {
		t.Errorf("expected name default, got %q", p.Name)
	}
	if p.SleepBaseSeconds != 30 {
		t.Errorf("expected sleep base 30, got %d", p.SleepBaseSeconds)
	}
	if p.JitterPct != 20 {
		t.Errorf("expected jitter 20, got %d", p.JitterPct)
	}
	if len(p.UserAgents) == 0 {
		t.Error("expected default user agents")
	}
	if err := p.Validate(); err != nil {
		t.Errorf("default profile invalid: %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		profile *Profile
		wantErr bool
	}{
		{"valid", &Profile{Name: "p", SleepBaseSeconds: 30, JitterPct: 20}, false},
		{"minimum sleep", &Profile{Name: "p", SleepBaseSeconds: 1, JitterPct: 0}, false},
		{"max jitter", &Profile{Name: "p", SleepBaseSeconds: 5, JitterPct: 100}, false},
		{"empty name", &Profile{SleepBaseSeconds: 30, JitterPct: 20}, true},
		{"zero sleep", &Profile{Name: "p", SleepBaseSeconds: 0, JitterPct: 20}, true},
		{"negative jitter", &Profile{Name: "p", SleepBaseSeconds: 30, JitterPct: -1}, true},
		{"jitter over 100", &Profile{Name: "p", SleepBaseSeconds: 30, JitterPct: 101}, true},
		{"nil profile", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.profile.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected nil error, got %v", err)
			}
		})
	}
}

func TestNextSleep_Bounds(t *testing.T) {
	tests := []struct {
		name    string
		profile *Profile
		min     time.Duration
		max     time.Duration
	}{
		{"default profile", Default(), 24 * time.Second, 36 * time.Second},
		{"wide jitter", &Profile{Name: "p", SleepBaseSeconds: 10, JitterPct: 50}, 5 * time.Second, 15 * time.Second},
		{"no jitter", &Profile{Name: "p", SleepBaseSeconds: 5, JitterPct: 0}, 5 * time.Second, 5 * time.Second},
		{"extreme jitter floored", &Profile{Name: "p", SleepBaseSeconds: 1, JitterPct: 100}, time.Second, 2 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 1000 {
				got := tt.profile.NextSleep()
				if got < tt.min || got > tt.max {
					t.Fatalf("NextSleep() = %v, want within [%v, %v]", got, tt.min, tt.max)
				}
			}
		})
	}
}

func TestNextSleep_NilProfile(t *testing.T) {
	var p *Profile
	for range 100 {
		got := p.NextSleep()
		if got < 24*time.Second || got > 36*time.Second {
			t.Fatalf("nil profile NextSleep() = %v, want within default bounds [24s, 36s]", got)
		}
	}
}

func TestNextUserAgent(t *testing.T) {
	configured := []string{"UA-One", "UA-Two", "UA-Three"}
	p := &Profile{Name: "p", SleepBaseSeconds: 30, JitterPct: 0, UserAgents: configured}

	allowed := make(map[string]bool, len(configured))
	for _, ua := range configured {
		allowed[ua] = true
	}
	seen := make(map[string]bool)
	for range 200 {
		ua := p.NextUserAgent()
		if !allowed[ua] {
			t.Fatalf("NextUserAgent() = %q, not in configured set", ua)
		}
		seen[ua] = true
	}
	if len(seen) != len(configured) {
		t.Errorf("expected all configured agents to be picked over 200 samples, saw %d of %d", len(seen), len(configured))
	}
}

func TestNextUserAgent_Empty(t *testing.T) {
	p := &Profile{Name: "p", SleepBaseSeconds: 30, JitterPct: 0}
	if got := p.NextUserAgent(); got != "" {
		t.Errorf("expected empty user agent, got %q", got)
	}
}

func TestNextUserAgent_NilProfile(t *testing.T) {
	var p *Profile
	if got := p.NextUserAgent(); got != "" {
		t.Errorf("expected empty user agent for nil profile, got %q", got)
	}
}
