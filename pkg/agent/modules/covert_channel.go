package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/yasindce1998/KubeDagger/pkg/covert"
)

type CovertChannel struct{}

func (m *CovertChannel) Name() string      { return "covert_channel" }
func (m *CovertChannel) Platform() []string { return []string{"linux"} }

func (m *CovertChannel) Execute(ctx context.Context, args map[string]string) (*Result, error) {
	channelType := args["channel"]
	if channelType == "" {
		return nil, fmt.Errorf("missing required arg: channel (icmp, dns, tcp_retransmit, ttl)")
	}

	data := args["data"]
	if data == "" {
		return nil, fmt.Errorf("missing required arg: data")
	}

	dst := args["dst"]
	if dst == "" {
		dst = "127.0.0.1"
	}

	registry := covert.NewRegistry()
	ch, err := registry.Get(channelType)
	if err != nil {
		return nil, fmt.Errorf("channel type %q: %w", channelType, err)
	}

	packets, err := ch.Encode([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	var summary []string
	summary = append(summary, fmt.Sprintf("channel: %s", ch.Name()))
	summary = append(summary, fmt.Sprintf("bandwidth: %d bps", ch.Bandwidth()))
	summary = append(summary, fmt.Sprintf("payload_size: %d bytes", len(data)))
	summary = append(summary, fmt.Sprintf("packets_generated: %d", len(packets)))
	summary = append(summary, fmt.Sprintf("destination: %s", dst))

	for i, pkt := range packets {
		if i >= 5 {
			summary = append(summary, fmt.Sprintf("  ... and %d more packets", len(packets)-5))
			break
		}
		summary = append(summary, fmt.Sprintf("  pkt[%d]: %d bytes -> %s:%d (%s)", i, len(pkt.Data), pkt.DstAddr, pkt.DstPort, pkt.Proto))
	}

	return &Result{
		Success: true,
		Output:  strings.Join(summary, "\n"),
	}, nil
}
