// Command export writes the public detection catalog for external validators.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/yasindce1998/KubeDagger/pkg/detectgen"
	"sigs.k8s.io/yaml"
)

func main() {
	out := flag.String("out", "", "output directory (required)")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	if err := export(*out); err != nil {
		log.Fatal(err)
	}
}

func export(dir string) error {
	for _, sub := range []string{"sigma", "falco"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return err
		}
	}
	var syscall, audit string
	for _, d := range detectgen.Catalog() {
		source, err := ruleSource(d.FalcoRule)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Technique, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sigma", d.Technique+".yaml"), []byte(d.SigmaRule), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "falco", d.Technique+".yaml"), []byte(d.FalcoRule), 0o600); err != nil {
			return err
		}
		// Source classification comes from the rule, not a parallel technique list.
		if source == "k8s_audit" {
			audit += d.FalcoRule + "\n"
		} else {
			syscall += d.FalcoRule + "\n"
		}
	}
	for name, content := range map[string]string{"syscall.yaml": syscall, "k8s_audit.yaml": audit} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(detectgen.Catalog(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "catalog.json"), data, 0o600)
}

func ruleSource(rule string) (string, error) {
	var rules []struct {
		Source string `json:"source"`
	}
	// Unmarshal through the same YAML library as the catalog's Go tests.
	if err := yaml.Unmarshal([]byte(rule), &rules); err != nil {
		return "", err
	}
	if len(rules) != 1 || (rules[0].Source != "syscall" && rules[0].Source != "k8s_audit") {
		return "", fmt.Errorf("expected one Falco rule with a supported explicit source")
	}
	return rules[0].Source, nil
}
