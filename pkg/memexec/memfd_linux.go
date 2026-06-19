package memexec

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func executeMemfd(payload []byte, argv []string) (int, error) {
	fd, err := unix.MemfdCreate("", unix.MFD_CLOEXEC)
	if err != nil {
		return 0, fmt.Errorf("memfd_create: %w", err)
	}

	f := os.NewFile(uintptr(fd), "")
	defer f.Close()

	if _, err := f.Write(payload); err != nil {
		return 0, fmt.Errorf("write payload: %w", err)
	}

	execPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	pid, err := forkExec(execPath, argv)
	if err != nil {
		return 0, fmt.Errorf("exec memfd: %w", err)
	}

	return pid, nil
}

func forkExec(path string, argv []string) (int, error) {
	if len(argv) == 0 {
		argv = []string{path}
	}

	cmd := exec.Command(path)
	cmd.Args = argv
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	return cmd.Process.Pid, nil
}
