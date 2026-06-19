//go:build !linux

package memexec

import "fmt"

func injectProcMem(_ int, _ []byte) error {
	return fmt.Errorf("procmem injection only available on linux")
}

func hollowProcess(_ int, _ []byte) error {
	return fmt.Errorf("process hollowing only available on linux")
}

func injectPtrace(_ int, _ []byte) error {
	return fmt.Errorf("ptrace injection only available on linux")
}

func executeMemfd(_ []byte, _ []string) (int, error) {
	return 0, fmt.Errorf("memfd_create only available on linux")
}
