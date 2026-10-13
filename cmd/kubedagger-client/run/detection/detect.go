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

// Package detection renders detection rules for executed KubeDagger
// techniques from the purple-team detection catalog.
package detection

import (
	"fmt"
	"os"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/detectgen"
)

// List prints all catalog techniques with their MITRE ATT&CK IDs.
func List(output string) error {
	catalog := detectgen.Catalog()

	var b strings.Builder
	b.WriteString("Technique          MITRE       Detection\n")
	b.WriteString("------------------ ---------- ----------------------------------------\n")
	for _, d := range catalog {
		b.WriteString(fmt.Sprintf("%-18s %-10s %s\n", d.Technique, d.MITRE, d.Name))
	}

	return writeOutput(b.String(), output)
}

// Generate renders a markdown detection coverage report for the given
// techniques. The techniques argument is a comma-separated list of technique
// keys, or "all" (or empty) for the full catalog.
func Generate(techniques, output string) error {
	list, err := parseTechniques(techniques)
	if err != nil {
		return err
	}

	md, err := detectgen.Generate(list)
	if err != nil {
		return err
	}

	return writeOutput(md, output)
}

// parseTechniques splits a comma-separated technique list, defaulting to the
// full catalog.
func parseTechniques(techniques string) ([]string, error) {
	t := strings.TrimSpace(techniques)
	if t == "" || t == "all" {
		return detectgen.Techniques(), nil
	}

	var list []string
	for _, part := range strings.Split(t, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			list = append(list, p)
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no valid techniques in --techniques value")
	}
	return list, nil
}

// writeOutput writes content to the output file or stdout.
func writeOutput(content, output string) error {
	if output != "" {
		return os.WriteFile(output, []byte(content), 0644)
	}
	fmt.Print(content)
	return nil
}
