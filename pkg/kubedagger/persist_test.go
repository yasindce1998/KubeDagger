package kubedagger

import (
	"testing"
)

func TestPersistConstants(t *testing.T) {
	if persistDir != "/usr/lib/kubedagger" {
		t.Errorf("persistDir = %q, want /usr/lib/kubedagger", persistDir)
	}
	if persistBinary != ".kd" {
		t.Errorf("persistBinary = %q, want .kd", persistBinary)
	}
	if serviceName != "kube-health-monitor" {
		t.Errorf("serviceName = %q, want kube-health-monitor", serviceName)
	}
	if serviceFile != "/etc/systemd/system/kube-health-monitor.service" {
		t.Errorf("serviceFile = %q, want /etc/systemd/system/kube-health-monitor.service", serviceFile)
	}
	if cronIdentifier != "# kubedagger-persist" {
		t.Errorf("cronIdentifier = %q, want # kubedagger-persist", cronIdentifier)
	}
}

func TestHasSystemd(t *testing.T) {
	_ = hasSystemd()
}
