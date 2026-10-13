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

// Package report builds engagement reports from recorded KubeDagger events.
// It renders both markdown and self-contained HTML with MITRE ATT&CK
// enrichment from the detection catalog.
package report

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yasindce1998/KubeDagger/pkg/detectgen"
	"github.com/yasindce1998/KubeDagger/pkg/events"
)

// Engagement holds report metadata supplied by the operator.
type Engagement struct {
	Title     string
	Operator  string
	Client    string
	StartDate string
	EndDate   string
	ScopeNote string
}

// techniqueStat aggregates per-technique execution statistics.
type techniqueStat struct {
	Technique  string
	MITRE      string
	Executions int
	Results    int
	Successes  int
}

// timelineRow is a single chronological event row.
type timelineRow struct {
	Timestamp string
	Agent     string
	Type      string
	Technique string
	Status    string
	Detail    string
}

// maxDetailLen is the maximum length of a timeline detail cell.
const maxDetailLen = 80

// GenerateMarkdown renders the engagement report as markdown.
func GenerateMarkdown(eng Engagement, evs []events.Event) string {
	sorted := sortByTimestamp(evs)
	agentTasks, statusCounts := taskStats(sorted)
	techStats := techniqueStats(sorted)

	var b strings.Builder

	title := eng.Title
	if title == "" {
		title = "KubeDagger Engagement Report"
	}
	b.WriteString(fmt.Sprintf("# %s\n\n", title))

	b.WriteString("## Engagement\n\n")
	writeField(&b, "Operator", eng.Operator)
	writeField(&b, "Client", eng.Client)
	writeField(&b, "Start date", eng.StartDate)
	writeField(&b, "End date", eng.EndDate)
	writeField(&b, "Scope", eng.ScopeNote)
	b.WriteString("\n")

	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- Total events: %d\n", len(sorted)))
	if len(agentTasks) > 0 {
		b.WriteString("\n### Tasks per agent\n\n")
		b.WriteString("| Agent | Tasks submitted |\n|---|---|\n")
		for _, row := range agentTasks {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", mdCell(row.agent), row.count))
		}
		b.WriteString("\n")
	}
	if len(statusCounts) > 0 {
		b.WriteString("### Tasks by status\n\n")
		b.WriteString("| Status | Tasks |\n|---|---|\n")
		for _, row := range statusCounts {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", mdCell(row.status), row.count))
		}
		b.WriteString("\n")
	}

	if len(techStats) > 0 {
		b.WriteString("### Techniques\n\n")
		b.WriteString("| Technique | MITRE | Executions | Success rate |\n|---|---|---|---|\n")
		for _, ts := range techStats {
			b.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n",
				mdCell(ts.Technique), mdCell(ts.MITRE), ts.Executions, successRate(ts)))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Timeline\n\n")
	if len(sorted) == 0 {
		b.WriteString("No events recorded.\n")
	} else {
		b.WriteString("| Timestamp | Agent | Type | Technique | Status | Detail |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, ev := range sorted {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				mdCell(ev.Timestamp.UTC().Format(time.RFC3339)),
				mdCell(ev.AgentID),
				mdCell(ev.Type),
				mdCell(ev.Technique),
				mdCell(ev.Status),
				mdCell(truncate(ev.Detail, maxDetailLen))))
		}
	}

	return b.String()
}

// GenerateHTML renders the engagement report as a self-contained, XSS-safe
// HTML document with inline CSS.
func GenerateHTML(eng Engagement, evs []events.Event) string {
	sorted := sortByTimestamp(evs)
	agentTasks, statusCounts := taskStats(sorted)
	techStats := techniqueStats(sorted)

	title := eng.Title
	if title == "" {
		title = "KubeDagger Engagement Report"
	}

	// agentRow, statusRow, and techniqueRow are view models for the HTML
	// template.
	type agentRow struct {
		Agent string
		Count int
	}
	type statusRow struct {
		Status string
		Count  int
	}
	type techniqueRow struct {
		Technique  string
		MITRE      string
		Executions int
		Rate       string
	}

	data := struct {
		Title       string
		Operator    string
		Client      string
		StartDate   string
		EndDate     string
		ScopeNote   string
		TotalEvents int
		AgentTasks  []agentRow
		Statuses    []statusRow
		Techniques  []techniqueRow
		Timeline    []timelineRow
	}{
		Title:       title,
		Operator:    eng.Operator,
		Client:      eng.Client,
		StartDate:   eng.StartDate,
		EndDate:     eng.EndDate,
		ScopeNote:   eng.ScopeNote,
		TotalEvents: len(sorted),
	}
	for _, r := range agentTasks {
		data.AgentTasks = append(data.AgentTasks, agentRow{r.agent, r.count})
	}
	for _, r := range statusCounts {
		data.Statuses = append(data.Statuses, statusRow{r.status, r.count})
	}
	for _, ts := range techStats {
		data.Techniques = append(data.Techniques, techniqueRow{
			Technique:  ts.Technique,
			MITRE:      ts.MITRE,
			Executions: ts.Executions,
			Rate:       successRate(ts),
		})
	}
	for _, ev := range sorted {
		data.Timeline = append(data.Timeline, timelineRow{
			Timestamp: ev.Timestamp.UTC().Format(time.RFC3339),
			Agent:     ev.AgentID,
			Type:      ev.Type,
			Technique: ev.Technique,
			Status:    ev.Status,
			Detail:    truncate(ev.Detail, maxDetailLen),
		})
	}

	var sb strings.Builder
	if err := htmlTemplate.Execute(&sb, data); err != nil {
		// The template is static and the data consists of plain strings, so
		// execution cannot fail in practice.
		return fmt.Sprintf("<html><body><h1>%s</h1><p>report rendering failed: %v</p></body></html>", title, err)
	}
	return sb.String()
}

const htmlTemplateText = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ .Title }}</title>
<style>
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 70rem; color: #1a1a1a; }
h1 { border-bottom: 2px solid #cc0000; padding-bottom: .4rem; }
h2 { margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #d0d0d0; padding: .4rem .6rem; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
.meta td { border: none; padding: .15rem .6rem .15rem 0; }
code { background: #f4f4f4; padding: .1rem .3rem; border-radius: 3px; }
</style>
</head>
<body>
<h1>{{ .Title }}</h1>

<h2>Engagement</h2>
<table class="meta">
{{- if .Operator }}<tr><th>Operator</th><td>{{ .Operator }}</td></tr>{{ end }}
{{- if .Client }}<tr><th>Client</th><td>{{ .Client }}</td></tr>{{ end }}
{{- if .StartDate }}<tr><th>Start date</th><td>{{ .StartDate }}</td></tr>{{ end }}
{{- if .EndDate }}<tr><th>End date</th><td>{{ .EndDate }}</td></tr>{{ end }}
{{- if .ScopeNote }}<tr><th>Scope</th><td>{{ .ScopeNote }}</td></tr>{{ end }}
</table>

<h2>Summary</h2>
<p>Total events: <strong>{{ .TotalEvents }}</strong></p>

{{- if .AgentTasks }}
<h3>Tasks per agent</h3>
<table>
<tr><th>Agent</th><th>Tasks submitted</th></tr>
{{ range .AgentTasks }}<tr><td>{{ .Agent }}</td><td>{{ .Count }}</td></tr>
{{ end }}</table>
{{- end }}

{{- if .Statuses }}
<h3>Tasks by status</h3>
<table>
<tr><th>Status</th><th>Tasks</th></tr>
{{ range .Statuses }}<tr><td>{{ .Status }}</td><td>{{ .Count }}</td></tr>
{{ end }}</table>
{{- end }}

{{- if .Techniques }}
<h3>Techniques</h3>
<table>
<tr><th>Technique</th><th>MITRE</th><th>Executions</th><th>Success rate</th></tr>
{{ range .Techniques }}<tr><td>{{ .Technique }}</td><td>{{ .MITRE }}</td><td>{{ .Executions }}</td><td>{{ .Rate }}</td></tr>
{{ end }}</table>
{{- end }}

<h2>Timeline</h2>
{{- if .Timeline }}
<table>
<tr><th>Timestamp</th><th>Agent</th><th>Type</th><th>Technique</th><th>Status</th><th>Detail</th></tr>
{{ range .Timeline }}<tr><td>{{ .Timestamp }}</td><td>{{ .Agent }}</td><td>{{ .Type }}</td><td>{{ .Technique }}</td><td>{{ .Status }}</td><td>{{ .Detail }}</td></tr>
{{ end }}</table>
{{- else }}
<p>No events recorded.</p>
{{- end }}

<p><small>Generated by KubeDagger report builder.</small></p>
</body>
</html>
`

var htmlTemplate = template.Must(template.New("report").Parse(htmlTemplateText))

// sortByTimestamp returns a copy of evs sorted by timestamp (stable).
func sortByTimestamp(evs []events.Event) []events.Event {
	out := make([]events.Event, len(evs))
	copy(out, evs)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out
}

// agentCount is a per-agent task submission count.
type agentCount struct {
	agent string
	count int
}

// statusCount is a per-status task result count.
type statusCount struct {
	status string
	count  int
}

// taskStats returns per-agent submitted-task counts and per-status
// completed-task counts, both deterministically ordered.
func taskStats(evs []events.Event) (agentTasks []agentCount, statusCounts []statusCount) {
	agents := map[string]int{}
	statuses := map[string]int{}
	for _, ev := range evs {
		switch ev.Type {
		case events.TypeTaskSubmitted:
			agents[ev.AgentID]++
		case events.TypeTaskResult:
			statuses[ev.Status]++
		}
	}

	agentKeys := make([]string, 0, len(agents))
	for k := range agents {
		agentKeys = append(agentKeys, k)
	}
	sort.Strings(agentKeys)
	for _, k := range agentKeys {
		agentTasks = append(agentTasks, agentCount{k, agents[k]})
	}

	statusKeys := make([]string, 0, len(statuses))
	for k := range statuses {
		statusKeys = append(statusKeys, k)
	}
	sort.Strings(statusKeys)
	for _, k := range statusKeys {
		statusCounts = append(statusCounts, statusCount{k, statuses[k]})
	}
	return agentTasks, statusCounts
}

// techniqueStats aggregates per-technique execution and success statistics,
// ordered by descending executions then technique name.
func techniqueStats(evs []events.Event) []techniqueStat {
	byTech := map[string]*techniqueStat{}
	var order []string
	for _, ev := range evs {
		if ev.Technique == "" {
			continue
		}
		ts, ok := byTech[ev.Technique]
		if !ok {
			ts = &techniqueStat{Technique: ev.Technique}
			byTech[ev.Technique] = ts
			order = append(order, ev.Technique)
		}
		switch ev.Type {
		case events.TypeTaskSubmitted:
			ts.Executions++
		case events.TypeTaskResult:
			ts.Results++
			if ev.Status == "success" {
				ts.Successes++
			}
		}
	}

	for _, t := range order {
		ts := byTech[t]
		ts.MITRE = mitreFor(t)
	}

	out := make([]techniqueStat, 0, len(order))
	for _, t := range order {
		out = append(out, *byTech[t])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Executions != out[j].Executions {
			return out[i].Executions > out[j].Executions
		}
		return out[i].Technique < out[j].Technique
	})
	return out
}

// mitreFor resolves a technique's ATT&CK ID from the detection catalog.
func mitreFor(technique string) string {
	if d, ok := detectgen.Lookup(technique); ok {
		return d.MITRE
	}
	return "-"
}

// successRate renders the success rate of a technique's task results.
func successRate(ts techniqueStat) string {
	if ts.Results == 0 {
		return "-"
	}
	return fmt.Sprintf("%d%%", ts.Successes*100/ts.Results)
}

// truncate shortens s to at most max runes.
func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max])
}

// mdCell makes a string safe for a markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// writeField writes a labeled field when the value is non-empty.
func writeField(b *strings.Builder, label, value string) {
	if value != "" {
		b.WriteString(fmt.Sprintf("- **%s:** %s\n", label, value))
	}
}
