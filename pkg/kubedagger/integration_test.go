//go:build integration

package kubedagger

import (
	"testing"
)

func TestBPFLoadAndAttach(t *testing.T) {
	kd := New(Options{
		DisableNetwork:        true,
		DisableBPFObfuscation: true,
	})

	if err := kd.Start(); err != nil {
		t.Fatalf("failed to start KUBEDagger: %v", err)
	}
	defer func() {
		if err := kd.Stop(); err != nil {
			t.Errorf("failed to stop KUBEDagger: %v", err)
		}
	}()

	maps := []string{"http_routes", "dns_table", "piped_progs", "comm_prog_key"}
	for _, name := range maps {
		m, _, err := kd.mainManager.GetMap(name)
		if err != nil {
			t.Errorf("map %q lookup error: %v", name, err)
		} else if m == nil {
			t.Errorf("map %q is nil", name)
		}
	}
}
