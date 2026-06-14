package mitre

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetTechniques(t *testing.T) {
	techs := GetTechniques()
	if len(techs) == 0 {
		t.Fatal("expected at least one technique")
	}

	ids := make(map[string]bool)
	for _, tech := range techs {
		if tech.ID == "" {
			t.Error("technique has empty ID")
		}
		if tech.Name == "" {
			t.Errorf("technique %s has empty name", tech.ID)
		}
		if tech.Tactic == "" {
			t.Errorf("technique %s has empty tactic", tech.ID)
		}
		if !tech.Enabled {
			t.Errorf("technique %s is not enabled", tech.ID)
		}
		if ids[tech.ID] {
			t.Errorf("duplicate technique ID: %s", tech.ID)
		}
		ids[tech.ID] = true
	}
}

func TestGetTechniquesCoversExpected(t *testing.T) {
	expected := []string{"T1525", "T1046", "T1005", "T1055", "T1071.004", "T1564.001", "T1003", "T1053.003"}
	techs := GetTechniques()
	ids := make(map[string]bool)
	for _, tech := range techs {
		ids[tech.ID] = true
	}

	for _, id := range expected {
		if !ids[id] {
			t.Errorf("expected technique %s not found", id)
		}
	}
}

func TestExportNavigatorJSON(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "layer.json")

	if err := ExportNavigatorJSON(outPath); err != nil {
		t.Fatalf("ExportNavigatorJSON failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var layer NavigatorLayer
	if err := json.Unmarshal(data, &layer); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if layer.Name != "KubeDagger Coverage" {
		t.Errorf("unexpected layer name: %s", layer.Name)
	}
	if layer.Domain != "enterprise-attack" {
		t.Errorf("unexpected domain: %s", layer.Domain)
	}
	if len(layer.Techniques) == 0 {
		t.Error("no techniques in output")
	}
	if len(layer.Gradient.Colors) == 0 {
		t.Error("no gradient colors")
	}
}

func TestExportMarkdown(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.md")

	if err := ExportMarkdown(outPath); err != nil {
		t.Fatalf("ExportMarkdown failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# KubeDagger") {
		t.Error("markdown missing header")
	}
	if !strings.Contains(content, "| Technique ID |") {
		t.Error("markdown missing table header")
	}
	if !strings.Contains(content, "T1525") {
		t.Error("markdown missing T1525 technique")
	}
	if !strings.Contains(content, "Coverage by Tactic") {
		t.Error("markdown missing tactic summary")
	}
}

func TestExportNavigatorJSONStdout(t *testing.T) {
	if err := ExportNavigatorJSON(""); err != nil {
		t.Fatalf("ExportNavigatorJSON to stdout failed: %v", err)
	}
}

func TestExportMarkdownStdout(t *testing.T) {
	if err := ExportMarkdown(""); err != nil {
		t.Fatalf("ExportMarkdown to stdout failed: %v", err)
	}
}
