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

package mitre

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ExportNavigatorJSON generates an ATT&CK Navigator layer JSON file
func ExportNavigatorJSON(output string) error {
	layer := NavigatorLayer{
		Name: "KubeDagger Coverage",
		Versions: Versions{
			Attack:    "14",
			Navigator: "4.9.1",
			Layer:     "4.5",
		},
		Domain:      "enterprise-attack",
		Description: "MITRE ATT&CK technique coverage for KubeDagger eBPF rootkit",
		Filters: Filters{
			Platforms: []string{"Linux", "Containers"},
		},
		Sorting: 0,
		Layout: Layout{
			Layout:       "side",
			AggregateF:   "average",
			ShowID:       true,
			ShowName:     true,
			ShowAggreg:   false,
			CountUnscor:  false,
		},
		HideDisable: false,
		Techniques:  techniques,
		Gradient: Gradient{
			Colors:   []string{"#ffffff", "#ff9933", "#ff6666"},
			MinValue: 0,
			MaxValue: 100,
		},
		LegendItems: []Legend{
			{Label: "Full implementation", Color: "#ff6666"},
			{Label: "Partial implementation", Color: "#ff9933"},
			{Label: "Not covered", Color: "#ffffff"},
		},
	}

	data, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal navigator layer: %w", err)
	}

	if output != "" {
		if err := os.WriteFile(output, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("ATT&CK Navigator layer written to: %s\n", output)
		return nil
	}

	fmt.Println(string(data))
	return nil
}

// ExportMarkdown generates a human-readable markdown report
func ExportMarkdown(output string) error {
	var sb strings.Builder

	sb.WriteString("# KubeDagger — MITRE ATT&CK Mapping\n\n")
	sb.WriteString("| Technique ID | Name | Tactic | Description |\n")
	sb.WriteString("|---|---|---|---|\n")

	for _, t := range techniques {
		fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", t.ID, t.Name, t.Tactic, t.Description)
	}

	fmt.Fprintf(&sb, "\n**Total techniques mapped:** %d\n", len(techniques))

	tacticMap := make(map[string]int)
	for _, t := range techniques {
		tacticMap[t.Tactic]++
	}
	sb.WriteString("\n## Coverage by Tactic\n\n")
	for tactic, count := range tacticMap {
		fmt.Fprintf(&sb, "- **%s**: %d techniques\n", tactic, count)
	}

	report := sb.String()
	if output != "" {
		if err := os.WriteFile(output, []byte(report), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("MITRE ATT&CK report written to: %s\n", output)
		return nil
	}

	fmt.Print(report)
	return nil
}
