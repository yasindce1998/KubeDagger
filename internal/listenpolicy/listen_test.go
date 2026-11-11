package listenpolicy

import "testing"

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8443": true, "127.0.0.2:0": true, "[::1]:8080": true,
		"[::ffff:127.0.0.1]:8080": true, "0.0.0.0:443": false, ":443": false,
		"[::]:443": false, "localhost:443": false, "10.0.0.1:443": false, "invalid": false,
	} {
		t.Run(addr, func(t *testing.T) {
			if got := IsLoopback(addr); got != want {
				t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
			}
		})
	}
}
