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

// Package malleable defines HTTP behaviour profiles (beacon sleep intervals,
// jitter, user agents, and extra headers) that shape C2 traffic patterns.
// Profiles are loaded from YAML and are nil-safe: a nil Profile falls back to
// sensible defaults.
package malleable

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

// randFloat returns a cryptographically secure pseudo-random float64 in [0, 1).
// Beacon timing must not be predictable from process state, so math/rand is
// deliberately avoided here.
func randFloat() float64 {
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0
	}
	return float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64+1)
}

// Profile shapes the timing and HTTP fingerprint of agent beaconing.
type Profile struct {
	Name             string            `yaml:"name" json:"name"`
	SleepBaseSeconds int               `yaml:"sleep_base_seconds" json:"sleep_base_seconds"`
	JitterPct        int               `yaml:"jitter_pct" json:"jitter_pct"` // 0-100
	UserAgents       []string          `yaml:"user_agents" json:"user_agents"`
	Headers          map[string]string `yaml:"headers" json:"headers"` // extra HTTP headers
}

// Load reads and validates a malleable profile from a YAML file.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("malleable: read %s: %w", path, err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("malleable: parse %s: %w", path, err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("malleable: %s: %w", path, err)
	}

	return &p, nil
}

// Default returns a browser-like default profile: 30s base sleep with 20%
// jitter and a rotation of common desktop user agents.
func Default() *Profile {
	return &Profile{
		Name:             "default",
		SleepBaseSeconds: 30,
		JitterPct:        20,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
			"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
		},
	}
}

// Validate checks that the profile is usable: non-empty name, sleep base of at
// least 1 second, and jitter between 0 and 100 percent.
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}
	if p.Name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if p.SleepBaseSeconds < 1 {
		return fmt.Errorf("sleep_base_seconds must be >= 1 (got %d)", p.SleepBaseSeconds)
	}
	if p.JitterPct < 0 || p.JitterPct > 100 {
		return fmt.Errorf("jitter_pct must be between 0 and 100 (got %d)", p.JitterPct)
	}
	return nil
}

// NextSleep returns the next beacon interval: the base sleep offset by a
// uniformly random jitter in [-jitter, +jitter]. The result is floored at one
// second so extreme jitter configurations cannot produce zero-length
// intervals. A nil profile uses the default 30s/20% behaviour.
func (p *Profile) NextSleep() time.Duration {
	base := 30 * time.Second
	jitterPct := 20
	if p != nil {
		if p.SleepBaseSeconds >= 1 {
			base = time.Duration(p.SleepBaseSeconds) * time.Second
		}
		jitterPct = p.JitterPct
	}
	if jitterPct < 0 {
		jitterPct = 0
	}
	if jitterPct > 100 {
		jitterPct = 100
	}

	jitter := time.Duration(float64(base) * float64(jitterPct) / 100.0)
	sleep := base + time.Duration((randFloat()*2-1)*float64(jitter))
	if sleep < time.Second {
		sleep = time.Second
	}
	return sleep
}

// NextUserAgent returns a randomly picked user agent, or "" when the profile
// has none configured.
func (p *Profile) NextUserAgent() string {
	if p == nil || len(p.UserAgents) == 0 {
		return ""
	}
	idx := int(randFloat() * float64(len(p.UserAgents)))
	if idx >= len(p.UserAgents) {
		idx = len(p.UserAgents) - 1
	}
	return p.UserAgents[idx]
}
