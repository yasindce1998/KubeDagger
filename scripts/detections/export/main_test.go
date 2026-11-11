package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yasindce1998/KubeDagger/pkg/detectgen"
	"sigs.k8s.io/yaml"
)

func TestExport(t *testing.T) {
	dir := t.TempDir()
	if err := export(dir); err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, source := range []string{"syscall", "k8s_audit"} {
		data, err := os.ReadFile(filepath.Join(dir, source+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var rules []map[string]any
		if err := yaml.Unmarshal(data, &rules); err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			if rule["source"] != source {
				t.Errorf("%s: unexpected rule source %v", source, rule["source"])
			}
			counts[source]++
		}
	}
	if counts["syscall"] == 0 || counts["k8s_audit"] == 0 || counts["syscall"]+counts["k8s_audit"] != len(detectgen.Catalog()) {
		t.Fatalf("exported rule counts: %v", counts)
	}
	for _, d := range detectgen.Catalog() {
		for format, want := range map[string]string{"falco": d.FalcoRule, "sigma": d.SigmaRule} {
			data, err := os.ReadFile(filepath.Join(dir, format, d.Technique+".yaml"))
			if err != nil || string(data) != want {
				t.Errorf("%s/%s: export differs from catalog (err=%v)", format, d.Technique, err)
			}
		}
	}
}

func TestRuleSourceFailsClosed(t *testing.T) {
	for _, rule := range []string{"[", "- rule: missing", "- source: unknown", "- source: syscall\n- source: k8s_audit"} {
		if _, err := ruleSource(rule); err == nil {
			t.Errorf("must reject invalid rule source: %q", rule)
		}
	}
}
