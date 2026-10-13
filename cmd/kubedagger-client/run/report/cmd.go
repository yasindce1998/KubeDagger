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

// Package report renders engagement reports from KubeDagger event JSONL
// files recorded by the C2 server.
package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/yasindce1998/KubeDagger/pkg/events"
	kubedaggerreport "github.com/yasindce1998/KubeDagger/pkg/report"
)

// Generate reads an events JSONL file and renders an engagement report.
// When html is true the report is rendered as a self-contained HTML
// document instead of markdown.
func Generate(eventsPath, output string, html bool, title, operator, client, start, end, scope string) error {
	if eventsPath == "" {
		return fmt.Errorf("--events is required (path to an events.jsonl file)")
	}

	evs, err := readEvents(eventsPath)
	if err != nil {
		return err
	}

	eng := kubedaggerreport.Engagement{
		Title:     title,
		Operator:  operator,
		Client:    client,
		StartDate: start,
		EndDate:   end,
		ScopeNote: scope,
	}

	var content string
	if html {
		content = kubedaggerreport.GenerateHTML(eng, evs)
	} else {
		content = kubedaggerreport.GenerateMarkdown(eng, evs)
	}

	if output != "" {
		return os.WriteFile(output, []byte(content), 0644)
	}
	fmt.Print(content)
	return nil
}

// readEvents loads events from a JSONL file (one JSON object per line).
func readEvents(path string) ([]events.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open events file: %w", err)
	}
	defer f.Close()

	var evs []events.Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		var ev events.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("events file line %d: %w", lineNo, err)
		}
		evs = append(evs, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read events file: %w", err)
	}
	return evs, nil
}
