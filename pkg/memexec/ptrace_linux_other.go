//go:build linux && !amd64

package memexec

import "fmt"

func injectPtrace(_ int, _ []byte) error {
	return fmt.Errorf("ptrace injection only available on linux/amd64")
}
