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

package report

import (
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/events"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func testEngagement() Engagement {
	return Engagement{
		Title:     "Red Team Engagement 2026-Q4",
		Operator:  "operator@example.com",
		Client:    "Example Corp",
		StartDate: "2026-10-01",
		EndDate:   "2026-10-13",
		ScopeNote: "Staging cluster only",
	}
}

func testEvents() []events.Event {
	return []events.Event{
		{ID: "1", Timestamp: ts("2026-10-10T10:00:00Z"), AgentID: "agent-a", Type: events.TypeAgentCheckin, Detail: "checkin"},
		{ID: "2", Timestamp: ts("2026-10-10T10:01:00Z"), AgentID: "agent-a", Type: events.TypeTaskSubmitted, TaskType: "sa_token", Technique: "sa_token"},
		{ID: "3", Timestamp: ts("2026-10-10T10:02:00Z"), AgentID: "agent-a", Type: events.TypeTaskResult, TaskType: "sa_token", Technique: "sa_token", Status: "success", Detail: "minted token for default/default"},
		{ID: "4", Timestamp: ts("2026-10-11T09:00:00Z"), AgentID: "agent-b", Type: events.TypeTaskSubmitted, TaskType: "daemonset", Technique: "daemonset"},
		{ID: "5", Timestamp: ts("2026-10-11T09:05:00Z"), AgentID: "agent-b", Type: events.TypeTaskSubmitted, TaskType: "daemonset", Technique: "daemonset"},
		{ID: "6", Timestamp: ts("2026-10-11T09:10:00Z"), AgentID: "agent-b", Type: events.TypeTaskResult, TaskType: "daemonset", Technique: "daemonset", Status: "success", Detail: "deployed kube-node-monitor"},
		{ID: "7", Timestamp: ts("2026-10-11T09:15:00Z"), AgentID: "agent-b", Type: events.TypeTaskResult, TaskType: "daemonset", Technique: "daemonset", Status: "error", Detail: "admission denied"},
		{ID: "8", Timestamp: ts("2026-10-12T12:00:00Z"), AgentID: "agent-b", Type: events.TypeTaskResult, TaskType: "unknown_tech", Technique: "unknown_tech", Status: "success", Detail: "ran"},
	}
}

func TestGenerateMarkdownStats(t *testing.T) {
	md := GenerateMarkdown(testEngagement(), testEvents())

	checks := []struct {
		name string
		want string
	}{
		{"total events", "Total events: 8"},
		{"agent-a task count", "| agent-a | 1 |"},
		{"agent-b task count", "| agent-b | 2 |"},
		{"status success count", "| success | 3 |"},
		{"status error count", "| error | 1 |"},
		{"sa_token executions", "| sa_token | T1552.001 | 1 | 100% |"},
		{"daemonset executions", "| daemonset | T1610 | 2 | 50% |"},
	}
	for _, c := range checks {
		if !strings.Contains(md, c.want) {
			t.Errorf("%s: markdown missing %q", c.name, c.want)
		}
	}
}

func TestGenerateMarkdownHeader(t *testing.T) {
	md := GenerateMarkdown(testEngagement(), testEvents())

	for _, want := range []string{
		"# Red Team Engagement 2026-Q4",
		"**Operator:** operator@example.com",
		"**Client:** Example Corp",
		"**Start date:** 2026-10-01",
		"**End date:** 2026-10-13",
		"**Scope:** Staging cluster only",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown header missing %q", want)
		}
	}
}

func TestGenerateMarkdownMITREEnrichment(t *testing.T) {
	md := GenerateMarkdown(testEngagement(), testEvents())

	if !strings.Contains(md, "T1552.001") {
		t.Error("markdown technique table missing MITRE ID for sa_token")
	}
	if !strings.Contains(md, "T1610") {
		t.Error("markdown technique table missing MITRE ID for daemonset")
	}
	if !strings.Contains(md, "| unknown_tech | - | 0 | 100% |") {
		t.Error("unmapped technique should show '-' as MITRE ID")
	}
}

func TestGenerateMarkdownTimelineSortedAndTruncated(t *testing.T) {
	evs := []events.Event{
		{
			ID:        "later",
			Timestamp: ts("2026-10-12T12:00:00Z"),
			AgentID:   "agent-b",
			Type:      events.TypeTaskResult,
			Technique: "sa_token",
			Status:    "success",
			Detail:    strings.Repeat("x", 120),
		},
		{
			ID:        "earlier",
			Timestamp: ts("2026-10-10T10:00:00Z"),
			AgentID:   "agent-a",
			Type:      events.TypeTaskSubmitted,
			Technique: "sa_token",
			Status:    "pending",
			Detail:    "first",
		},
	}

	md := GenerateMarkdown(testEngagement(), evs)

	if !strings.Contains(md, strings.Repeat("x", 80)) {
		t.Error("timeline detail should contain 80 truncated characters")
	}
	if strings.Contains(md, strings.Repeat("x", 81)) {
		t.Error("timeline detail should be truncated to 80 characters")
	}
	if !strings.Contains(md, "| first |") && !strings.Contains(md, "| first ") {
		t.Error("timeline should contain detail 'first'")
	}

	earlierIdx := strings.Index(md, "2026-10-10T10:00:00Z")
	laterIdx := strings.Index(md, "2026-10-12T12:00:00Z")
	if earlierIdx == -1 || laterIdx == -1 {
		t.Fatal("timeline rows missing")
	}
	if earlierIdx > laterIdx {
		t.Error("timeline should be sorted by timestamp ascending")
	}
}

func TestGenerateMarkdownEmpty(t *testing.T) {
	md := GenerateMarkdown(testEngagement(), nil)

	if !strings.Contains(md, "Total events: 0") {
		t.Error("empty report should show zero total events")
	}
	if !strings.Contains(md, "No events recorded.") {
		t.Error("empty report should render a placeholder timeline")
	}
	if strings.Contains(md, "Tasks per agent") {
		t.Error("empty report should not render agent stats")
	}
}

func TestGenerateMarkdownDefaultTitle(t *testing.T) {
	md := GenerateMarkdown(Engagement{}, nil)
	if !strings.Contains(md, "# KubeDagger Engagement Report") {
		t.Error("empty engagement should fall back to default title")
	}
}

func TestGenerateHTMLContent(t *testing.T) {
	html := GenerateHTML(testEngagement(), testEvents())

	for _, want := range []string{
		"<title>Red Team Engagement 2026-Q4</title>",
		"Total events: <strong>8</strong>",
		"<td>agent-a</td><td>1</td>",
		"<td>agent-b</td><td>2</td>",
		"<td>success</td><td>3</td>",
		"<td>sa_token</td><td>T1552.001</td><td>1</td><td>100%</td>",
		"<td>daemonset</td><td>T1610</td><td>2</td><td>50%</td>",
		"minted token for default/default",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("html missing %q", want)
		}
	}
}

func TestGenerateHTMLXSSSafe(t *testing.T) {
	evs := []events.Event{
		{
			ID:        "1",
			Timestamp: ts("2026-10-10T10:00:00Z"),
			AgentID:   "agent-a",
			Type:      events.TypeTaskResult,
			Technique: "sa_token",
			Status:    "success",
			Detail:    `<script>alert("xss")</script>`,
		},
	}
	evs[0].AgentID = `<script>alert("agent")</script>`

	html := GenerateHTML(testEngagement(), evs)

	if strings.Contains(html, "<script>") {
		t.Error("html output contains unescaped <script>")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("html output should escape script tags")
	}
}

func TestGenerateHTMLEmpty(t *testing.T) {
	html := GenerateHTML(Engagement{}, nil)

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("html output should be a full document")
	}
	if !strings.Contains(html, "Total events: <strong>0</strong>") {
		t.Error("empty html report should show zero total events")
	}
	if !strings.Contains(html, "No events recorded.") {
		t.Error("empty html report should render a placeholder timeline")
	}
	if strings.Contains(html, "Tasks per agent") {
		t.Error("empty html report should not render agent stats")
	}
}
