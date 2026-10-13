/*
Copyright © 2023 MOHAMMED YASIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMesh_ListenRelayAndStop(t *testing.T) {
	// Fake C2 server that records hits.
	c2Hits := 0
	fakeC2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c2Hits++
		fmt.Fprintf(w, "c2-response path=%s", r.URL.Path)
	}))
	defer fakeC2.Close()

	m := NewMesh()
	ctx := context.Background()

	// Start relay on an ephemeral port.
	result, err := m.Execute(ctx, map[string]string{
		"action": "listen",
		"port":   "0",
		"server": fakeC2.URL,
	})
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("listen not successful: %s", result.Error)
	}

	re := regexp.MustCompile(`listening on [^ ]+:(\d+)`)
	match := re.FindStringSubmatch(result.Output)
	if match == nil {
		t.Fatalf("could not parse listen address from output: %q", result.Output)
	}
	port := match[1]

	// Route a request through the relay.
	relayURL := "http://127.0.0.1:" + port + "/checkin"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(relayURL)
	if err != nil {
		t.Fatalf("request through relay failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 through relay, got %d", resp.StatusCode)
	}
	if c2Hits != 1 {
		t.Errorf("expected fake C2 to be hit once, got %d", c2Hits)
	}

	// List peers must show the relay.
	listResult, err := m.Execute(ctx, map[string]string{"action": "peers"})
	if err != nil {
		t.Fatalf("peers failed: %v", err)
	}
	if !listResult.Success {
		t.Fatalf("peers not successful: %s", listResult.Error)
	}
	if !regexp.MustCompile(`\d+ -> ` + regexp.QuoteMeta(fakeC2.URL)).MatchString(listResult.Output) {
		t.Errorf("expected relay listing with upstream %s, got:\n%s", fakeC2.URL, listResult.Output)
	}

	// Stop the relay.
	stopResult, err := m.Execute(ctx, map[string]string{"action": "stop", "port": port})
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if !stopResult.Success {
		t.Fatalf("stop not successful: %s", stopResult.Error)
	}

	// After stop, a new relay can bind the same port and requests fail.
	resp, err = http.Get(relayURL)
	if err == nil {
		resp.Body.Close()
		t.Error("expected request through stopped relay to fail")
	}
}

func TestMesh_InvalidArgs(t *testing.T) {
	m := NewMesh()
	ctx := context.Background()

	tests := []struct {
		name      string
		args      map[string]string
		wantError string
	}{
		{
			name:      "missing server",
			args:      map[string]string{"action": "listen"},
			wantError: "requires server argument",
		},
		{
			name:      "invalid port",
			args:      map[string]string{"action": "listen", "server": "http://c2", "port": "notaport"},
			wantError: "invalid port",
		},
		{
			name:      "invalid server url",
			args:      map[string]string{"action": "listen", "server": "://bad"},
			wantError: "invalid server URL",
		},
		{
			name:      "unknown action",
			args:      map[string]string{"action": "frobnicate"},
			wantError: "unknown action",
		},
		{
			name:      "stop non-existent relay",
			args:      map[string]string{"action": "stop", "port": "59999"},
			wantError: "no mesh relay running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.Execute(ctx, tt.args)
			if err == nil && result.Success {
				t.Fatalf("expected failure, got result: %+v err: %v", result, err)
			}
			var target string
			if err != nil {
				target = err.Error()
			} else {
				target = result.Error
			}
			if !strings.Contains(target, tt.wantError) {
				t.Errorf("expected error containing %q, got %q", tt.wantError, target)
			}
		})
	}
}
