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

package detectgen

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// expectedTechniques are the technique keys the catalog must cover. They
// match events.Event.Technique values.
var expectedTechniques = []string{
	"sa_token",
	"k8s_discovery",
	"escape",
	"daemonset",
	"webhook_deploy",
	"crd_backdoor",
	"dns_exfil",
	"k8s_c2",
	"memexec",
	"log_tamper",
	"antiforensics",
	"honeypot_detect",
	"cloud_metadata",
	"cloud_evasion",
	"cicd_poison",
	"service_mesh",
	"covert_channel",
	"polymorph",
}

func TestCatalogCompleteness(t *testing.T) {
	catalog := Catalog()

	if len(catalog) != len(expectedTechniques) {
		t.Fatalf("catalog has %d entries, want %d", len(catalog), len(expectedTechniques))
	}

	seen := make(map[string]bool, len(catalog))
	for _, d := range catalog {
		if d.Technique == "" {
			t.Error("catalog entry with empty Technique")
		}
		if d.MITRE == "" {
			t.Errorf("technique %q: empty MITRE", d.Technique)
		}
		if d.Name == "" {
			t.Errorf("technique %q: empty Name", d.Technique)
		}
		if d.Description == "" {
			t.Errorf("technique %q: empty Description", d.Technique)
		}
		if len(d.AuditEvents) == 0 {
			t.Errorf("technique %q: no audit events", d.Technique)
		}
		if seen[d.Technique] {
			t.Errorf("duplicate technique key %q", d.Technique)
		}
		seen[d.Technique] = true
	}

	for _, key := range expectedTechniques {
		if !seen[key] {
			t.Errorf("catalog missing technique %q", key)
		}
	}
}

func TestRuleYAMLValidity(t *testing.T) {
	for _, d := range Catalog() {
		var falcoRules []map[string]interface{}
		if err := yaml.Unmarshal([]byte(d.FalcoRule), &falcoRules); err != nil {
			t.Errorf("technique %q: invalid Falco rule YAML: %v", d.Technique, err)
			continue
		}
		if len(falcoRules) != 1 {
			t.Errorf("technique %q: Falco rule should be a single-item list, got %d", d.Technique, len(falcoRules))
			continue
		}
		rule := falcoRules[0]
		for _, field := range []string{"rule", "desc", "condition", "output", "priority", "tags"} {
			if _, ok := rule[field]; !ok {
				t.Errorf("technique %q: Falco rule missing field %q", d.Technique, field)
			}
		}

		var sigmaRule map[string]interface{}
		if err := yaml.Unmarshal([]byte(d.SigmaRule), &sigmaRule); err != nil {
			t.Errorf("technique %q: invalid Sigma rule YAML: %v", d.Technique, err)
			continue
		}
		for _, field := range []string{"title", "id", "status", "description", "logsource", "detection", "level", "tags"} {
			if _, ok := sigmaRule[field]; !ok {
				t.Errorf("technique %q: Sigma rule missing field %q", d.Technique, field)
			}
		}
		logsource, ok := sigmaRule["logsource"].(map[string]interface{})
		if !ok {
			t.Errorf("technique %q: Sigma logsource must be a mapping", d.Technique)
		} else {
			category, _ := logsource["category"].(string)
			if category == "" {
				t.Errorf("technique %q: Sigma logsource missing category", d.Technique)
			}
		}
		detection, ok := sigmaRule["detection"].(map[string]interface{})
		if !ok {
			t.Errorf("technique %q: Sigma detection must be a mapping", d.Technique)
		} else if _, ok := detection["condition"]; !ok {
			t.Errorf("technique %q: Sigma detection missing condition", d.Technique)
		}
	}
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name      string
		technique string
		wantOK    bool
		wantMITRE string
	}{
		{"hit sa_token", "sa_token", true, "T1552.001"},
		{"hit k8s_discovery", "k8s_discovery", true, "T1613"},
		{"hit escape", "escape", true, "T1611"},
		{"hit polymorph", "polymorph", true, "T1027"},
		{"hit crd_backdoor", "crd_backdoor", true, "T1098"},
		{"miss unknown", "does_not_exist", false, ""},
		{"miss empty", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, ok := Lookup(tt.technique)
			if ok != tt.wantOK {
				t.Fatalf("Lookup(%q) ok = %v, want %v", tt.technique, ok, tt.wantOK)
			}
			if ok && d.MITRE != tt.wantMITRE {
				t.Errorf("Lookup(%q).MITRE = %q, want %q", tt.technique, d.MITRE, tt.wantMITRE)
			}
		})
	}
}

func TestTechniquesSorted(t *testing.T) {
	keys := Techniques()
	if len(keys) != len(expectedTechniques) {
		t.Fatalf("Techniques() = %d keys, want %d", len(keys), len(expectedTechniques))
	}
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			t.Errorf("Techniques() not sorted: %q >= %q", keys[i-1], keys[i])
		}
	}
}

func TestGenerate(t *testing.T) {
	md, err := Generate([]string{"sa_token", "polymorph", "not_a_technique"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.Contains(md, "# KubeDagger Detection Coverage Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(md, "## Summary") {
		t.Error("missing summary section")
	}
	if !strings.Contains(md, "| sa_token | T1552.001 |") {
		t.Error("missing summary table row for sa_token")
	}
	if !strings.Contains(md, "## sa_token — T1552.001") {
		t.Error("missing per-technique section for sa_token")
	}
	if !strings.Contains(md, "## polymorph — T1027") {
		t.Error("missing per-technique section for polymorph")
	}
	if !strings.Contains(md, "```yaml") {
		t.Error("missing fenced YAML code blocks")
	}
	if !strings.Contains(md, "serviceaccounts/token") {
		t.Error("missing Falco/Sigma rule content for sa_token")
	}
	if !strings.Contains(md, "## Detection gaps") {
		t.Error("missing gaps section for unknown technique")
	}
	if !strings.Contains(md, "- not_a_technique") {
		t.Error("unknown technique not listed in gaps")
	}
	if !strings.Contains(md, "no detection mapping") {
		t.Error("summary does not mark unknown technique as no detection mapping")
	}
}

func TestGenerateAllTechniques(t *testing.T) {
	md, err := Generate(Techniques())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, key := range expectedTechniques {
		if !strings.Contains(md, "## "+key+" — ") {
			t.Errorf("missing section for technique %q", key)
		}
	}
	if strings.Contains(md, "## Detection gaps") {
		t.Error("gaps section should not appear when all techniques are mapped")
	}
}

func TestGenerateEmpty(t *testing.T) {
	if _, err := Generate(nil); err == nil {
		t.Error("Generate(nil) should return an error")
	}
	if _, err := Generate([]string{}); err == nil {
		t.Error("Generate([]) should return an error")
	}
}
