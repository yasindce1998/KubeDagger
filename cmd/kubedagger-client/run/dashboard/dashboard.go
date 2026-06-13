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

package dashboard

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tab int

const (
	tabFlows tab = iota
	tabFSWatch
	tabDocker
	tabPostgres
	tabCount
)

var tabNames = []string{"Flows", "FS Watch", "Docker", "Postgres"}

type Model struct {
	target      string
	refreshRate time.Duration
	activeTab   tab
	width       int
	height      int
	flows       []FlowEntry
	watches     []WatchEntry
	images      []ImageEntry
	credentials []CredEntry
	lastUpdate  time.Time
	err         error
	quitting    bool
}

type FlowEntry struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Proto   string
	Type    string
}

type WatchEntry struct {
	Path        string
	InContainer bool
	Active      bool
}

type ImageEntry struct {
	Original string
	Override string
	Action   string
}

type CredEntry struct {
	Role   string
	Secret string
}

type tickMsg time.Time
type pollResultMsg struct {
	flows       []FlowEntry
	watches     []WatchEntry
	images      []ImageEntry
	credentials []CredEntry
	err         error
}

func Run(target string, refreshRate int) error {
	m := Model{
		target:      target,
		refreshRate: time.Duration(refreshRate) * time.Second,
		activeTab:   tabFlows,
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(m.refreshRate), pollCmd(m.target))
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "tab", "right", "l":
			m.activeTab = (m.activeTab + 1) % tabCount
		case "shift+tab", "left", "h":
			m.activeTab = (m.activeTab - 1 + tabCount) % tabCount
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		return m, tea.Batch(tickCmd(m.refreshRate), pollCmd(m.target))

	case pollResultMsg:
		m.lastUpdate = time.Now()
		m.err = msg.err
		if msg.err == nil {
			m.flows = msg.flows
			m.watches = msg.watches
			m.images = msg.images
			m.credentials = msg.credentials
		}
	}

	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	header := m.renderHeader()
	tabs := m.renderTabs()
	content := m.renderContent()
	status := m.renderStatus()

	return fmt.Sprintf("%s\n%s\n%s\n%s", header, tabs, content, status)
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF6666")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#FF6666")).
			Padding(0, 2)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#888888")).
				Padding(0, 2)

	contentStyle = lipgloss.NewStyle().
			Padding(1, 2)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Padding(0, 1)

	errStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Bold(true)
)

func (m Model) renderHeader() string {
	return titleStyle.Render("⚡ KubeDagger Dashboard")
}

func (m Model) renderTabs() string {
	var tabs string
	for i, name := range tabNames {
		if tab(i) == m.activeTab {
			tabs += activeTabStyle.Render(name)
		} else {
			tabs += inactiveTabStyle.Render(name)
		}
	}
	return tabs
}

func (m Model) renderContent() string {
	var content string
	switch m.activeTab {
	case tabFlows:
		content = m.renderFlows()
	case tabFSWatch:
		content = m.renderWatches()
	case tabDocker:
		content = m.renderImages()
	case tabPostgres:
		content = m.renderCredentials()
	}
	return contentStyle.Render(content)
}

func (m Model) renderFlows() string {
	if len(m.flows) == 0 {
		return "No network flows captured yet."
	}
	s := fmt.Sprintf("%-18s %-7s %-18s %-7s %-6s %-6s\n",
		"Source IP", "Port", "Dest IP", "Port", "Proto", "Type")
	s += "─────────────────────────────────────────────────────────────────────\n"
	for _, f := range m.flows {
		s += fmt.Sprintf("%-18s %-7d %-18s %-7d %-6s %-6s\n",
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Proto, f.Type)
	}
	return s
}

func (m Model) renderWatches() string {
	if len(m.watches) == 0 {
		return "No filesystem watches active."
	}
	s := fmt.Sprintf("%-40s %-12s %-8s\n", "Path", "Container", "Active")
	s += "─────────────────────────────────────────────────────────────────\n"
	for _, w := range m.watches {
		container := "no"
		if w.InContainer {
			container = "yes"
		}
		active := "passive"
		if w.Active {
			active = "active"
		}
		s += fmt.Sprintf("%-40s %-12s %-8s\n", w.Path, container, active)
	}
	return s
}

func (m Model) renderImages() string {
	if len(m.images) == 0 {
		return "No Docker image overrides configured."
	}
	s := fmt.Sprintf("%-30s %-30s %-10s\n", "Original", "Override", "Action")
	s += "─────────────────────────────────────────────────────────────────────\n"
	for _, img := range m.images {
		s += fmt.Sprintf("%-30s %-30s %-10s\n", img.Original, img.Override, img.Action)
	}
	return s
}

func (m Model) renderCredentials() string {
	if len(m.credentials) == 0 {
		return "No PostgreSQL credentials captured."
	}
	s := fmt.Sprintf("%-30s %-40s\n", "Role", "Secret")
	s += "─────────────────────────────────────────────────────────────────────\n"
	for _, c := range m.credentials {
		s += fmt.Sprintf("%-30s %-40s\n", c.Role, c.Secret)
	}
	return s
}

func (m Model) renderStatus() string {
	status := fmt.Sprintf("Last update: %s | Target: %s | [Tab] switch pane | [q] quit",
		m.lastUpdate.Format("15:04:05"), m.target)
	if m.err != nil {
		status += " | " + errStyle.Render(fmt.Sprintf("Error: %v", m.err))
	}
	return statusStyle.Render(status)
}
