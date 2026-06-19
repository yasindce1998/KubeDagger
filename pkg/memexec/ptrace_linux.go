package memexec

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func injectPtrace(pid int, payload []byte) error {
	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("ptrace attach pid %d: %w", pid, err)
	}

	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		_ = unix.PtraceDetach(pid)
		return fmt.Errorf("wait after attach: %w", err)
	}

	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		_ = unix.PtraceDetach(pid)
		return fmt.Errorf("get regs: %w", err)
	}

	addr := regs.Rip

	wordSize := int(unsafe.Sizeof(uintptr(0)))
	for i := 0; i < len(payload); i += wordSize {
		var word uint64
		remaining := len(payload) - i
		if remaining >= wordSize {
			word = binary.LittleEndian.Uint64(payload[i : i+wordSize])
		} else {
			buf := make([]byte, wordSize)
			copy(buf, payload[i:])
			word = binary.LittleEndian.Uint64(buf)
		}

		_, err := unix.PtracePokeData(pid, uintptr(addr)+uintptr(i), []byte{
			byte(word), byte(word >> 8), byte(word >> 16), byte(word >> 24),
			byte(word >> 32), byte(word >> 40), byte(word >> 48), byte(word >> 56),
		})
		if err != nil {
			_ = unix.PtraceDetach(pid)
			return fmt.Errorf("poke at offset %d: %w", i, err)
		}
	}

	regs.Rip = addr
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		_ = unix.PtraceDetach(pid)
		return fmt.Errorf("set regs: %w", err)
	}

	if err := unix.PtraceDetach(pid); err != nil {
		return fmt.Errorf("detach: %w", err)
	}

	if err := unix.Kill(pid, unix.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT: %w", err)
	}

	return nil
}
