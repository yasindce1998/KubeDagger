package antiforensics

import (
	"fmt"
	"sync"
)

type Controller struct {
	mu          sync.Mutex
	filterPIDs  map[uint32]bool
	filterPaths map[string][]string
	active      bool
}

func NewController() *Controller {
	return &Controller{
		filterPIDs:  make(map[uint32]bool),
		filterPaths: make(map[string][]string),
	}
}

func (c *Controller) SuppressAuditForPID(pid uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filterPIDs[pid] = true
	return nil
}

func (c *Controller) RemoveAuditFilter(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.filterPIDs, pid)
}

func (c *Controller) FilterLogReads(path, pattern string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if path == "" || pattern == "" {
		return fmt.Errorf("path and pattern are required")
	}

	c.filterPaths[path] = append(c.filterPaths[path], pattern)
	return nil
}

func (c *Controller) RemoveLogFilter(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.filterPaths, path)
}

func (c *Controller) GetFilteredPIDs() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	pids := make([]uint32, 0, len(c.filterPIDs))
	for pid := range c.filterPIDs {
		pids = append(pids, pid)
	}
	return pids
}

func (c *Controller) GetFilteredPaths() map[string][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string][]string, len(c.filterPaths))
	for k, v := range c.filterPaths {
		patterns := make([]string, len(v))
		copy(patterns, v)
		result[k] = patterns
	}
	return result
}

func (c *Controller) Activate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = true
	return nil
}

func (c *Controller) Deactivate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
}

func (c *Controller) IsActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}
