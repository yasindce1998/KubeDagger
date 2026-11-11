package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRejectUnsafeStartup(t *testing.T) {
	if os.Getenv("KUBEDAGGER_STARTUP_TEST") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				break
			}
		}
		flag.CommandLine = flag.NewFlagSet("kubedagger-server", flag.ExitOnError)
		main()
		return
	}

	for _, tt := range []struct {
		name     string
		args     []string
		envToken string
		want     string
	}{
		{name: "plaintext wildcard", args: []string{"-plaintext"}, want: "plaintext development mode must bind"},
		{name: "missing UI token", args: []string{"-plaintext", "-listen", "127.0.0.1:0", "-webui", "127.0.0.1:0"}, want: "requires an explicit authentication token"},
		{name: "old default UI token", args: []string{"-plaintext", "-listen", "127.0.0.1:0", "-webui", "127.0.0.1:0", "-webui-token", "kubedagger"}, want: "old default is not allowed"},
		{name: "public HTTP UI with environment credential", args: []string{"-plaintext", "-listen", "127.0.0.1:0", "-webui", "0.0.0.0:0"}, envToken: "test-secret", want: "web UI HTTP must bind"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestRejectUnsafeStartup$", "--"}, tt.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "KUBEDAGGER_STARTUP_TEST=1", "KUBEDAGGER_WEBUI_TOKEN="+tt.envToken)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("unsafe startup did not fail before listening")
			}
			if err == nil || !strings.Contains(string(out), tt.want) {
				t.Fatalf("startup error = %v, output = %s; want %q", err, out, tt.want)
			}
		})
	}
}
