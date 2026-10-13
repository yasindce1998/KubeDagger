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

// Package scope defines an optional allow-list policy restricting which
// Kubernetes namespaces, domains, and network ranges operator-submitted tasks
// may target. A nil or empty Scope allows everything, so enforcement is fully
// backwards compatible when no policy is configured.
package scope

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"
)

// Scope is an allow-list policy for task targets. Each list restricts its own
// dimension independently; an empty list means "no restriction" for that
// dimension.
type Scope struct {
	Namespaces []string `yaml:"namespaces" json:"namespaces"` // allowed k8s namespaces; "*" = all
	Domains    []string `yaml:"domains" json:"domains"`       // allowed hostnames/domains; ".example.com" covers subdomains; "*" = all
	CIDRs      []string `yaml:"cidrs" json:"cidrs"`           // allowed network ranges (CIDR notation); "*" = all
}

// Load reads a scope policy from a YAML file. CIDR entries are validated at
// load time so misconfigured policies fail fast instead of silently never
// matching.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scope: read %s: %w", path, err)
	}

	var s Scope
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("scope: parse %s: %w", path, err)
	}

	for _, cidr := range s.CIDRs {
		c := strings.TrimSpace(cidr)
		if c == "*" {
			continue
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			return nil, fmt.Errorf("scope: %s: invalid cidr %q", path, cidr)
		}
	}

	return &s, nil
}

// Empty reports whether no restrictions are configured. An empty (or nil)
// scope allows everything.
func (s *Scope) Empty() bool {
	return s == nil || (len(s.Namespaces) == 0 && len(s.Domains) == 0 && len(s.CIDRs) == 0)
}

// AllowsNamespace reports whether the given Kubernetes namespace is allowed.
// A nil scope or empty namespace list allows all namespaces.
func (s *Scope) AllowsNamespace(ns string) bool {
	if s == nil || len(s.Namespaces) == 0 {
		return true
	}
	ns = strings.TrimSpace(ns)
	for _, allowed := range s.Namespaces {
		if allowed == "*" || strings.EqualFold(strings.TrimSpace(allowed), ns) {
			return true
		}
	}
	return false
}

// AllowsHost reports whether the given host is allowed. Ports are stripped,
// comparison is case-insensitive, "*" allows any host, plain entries match
// exactly, and dot-prefixed entries (".example.com") match the apex domain
// and any subdomain.
func (s *Scope) AllowsHost(host string) bool {
	if s == nil || len(s.Domains) == 0 {
		return true
	}
	host = normalizeHost(host)
	if host == "" {
		return true
	}
	for _, allowed := range s.Domains {
		d := strings.ToLower(strings.TrimSpace(allowed))
		switch {
		case d == "*" || d == host:
			return true
		case strings.HasPrefix(d, "."):
			apex := d[1:]
			if host == apex || strings.HasSuffix(host, d) {
				return true
			}
		}
	}
	return false
}

// AllowsIP reports whether the given IP is inside one of the allowed CIDR
// ranges. A nil scope or empty CIDR list allows all addresses; an
// unparseable IP is denied when CIDR restrictions are configured.
func (s *Scope) AllowsIP(ip string) bool {
	if s == nil || len(s.CIDRs) == 0 {
		return true
	}
	if h, _, err := net.SplitHostPort(strings.TrimSpace(ip)); err == nil {
		ip = h
	}
	parsed := net.ParseIP(strings.Trim(strings.TrimSpace(ip), "[]"))
	if parsed == nil {
		return false
	}
	for _, cidr := range s.CIDRs {
		c := strings.TrimSpace(cidr)
		if c == "*" {
			return true
		}
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// CheckTask validates a task payload against the scope policy. It inspects
// payload keys for scope-relevant values: "namespace"/"ns" (namespaces),
// "host"/"target"/"domain" (domains), "ip"/"addr" (CIDRs), and "url" (host
// extracted from the URL; IP literals are checked against CIDRs, hostnames
// against domains). All violations are collected and returned as a single
// error. A nil or empty scope allows everything.
func (s *Scope) CheckTask(taskType string, payload map[string]string) error {
	if s == nil || s.Empty() || len(payload) == 0 {
		return nil
	}

	var violations []string
	for _, key := range slices.Sorted(maps.Keys(payload)) {
		value := strings.TrimSpace(payload[key])
		if value == "" {
			continue
		}
		switch key {
		case "namespace", "ns":
			if !s.AllowsNamespace(value) {
				violations = append(violations, fmt.Sprintf("namespace %q not in allowed namespaces", value))
			}
		case "host", "target", "domain":
			if !s.AllowsHost(value) {
				violations = append(violations, fmt.Sprintf("host %q not in allowed domains", value))
			}
		case "ip", "addr":
			if !s.AllowsIP(value) {
				violations = append(violations, fmt.Sprintf("ip %q not in allowed cidrs", value))
			}
		case "url":
			u, err := url.Parse(value)
			if err != nil {
				violations = append(violations, fmt.Sprintf("url %q is invalid", value))
				continue
			}
			if u.Host == "" {
				continue
			}
			host := u.Hostname()
			if net.ParseIP(host) != nil {
				if !s.AllowsIP(host) {
					violations = append(violations, fmt.Sprintf("url %q ip %q not in allowed cidrs", value, host))
				}
			} else if !s.AllowsHost(host) {
				violations = append(violations, fmt.Sprintf("url %q host %q not in allowed domains", value, host))
			}
		}
	}

	if len(violations) == 0 {
		return nil
	}
	detail := strings.Join(violations, "; ")
	if taskType != "" {
		return fmt.Errorf("%s: %s", taskType, detail)
	}
	return errors.New(detail)
}

// normalizeHost lowercases a host value and strips any port and IPv6
// brackets.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}
