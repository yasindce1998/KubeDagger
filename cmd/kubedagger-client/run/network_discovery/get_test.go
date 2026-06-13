package network_discovery

import (
	"encoding/binary"
	"testing"

	"github.com/yasindce1998/KubeDagger/cmd/kubedagger-client/run/utils"
	"github.com/yasindce1998/KubeDagger/pkg/model"
)

func TestFlowIsPassive(t *testing.T) {
	tests := []struct {
		ft   model.FlowType
		want bool
	}{
		{model.IngressFlow, true},
		{model.EgressFlow, true},
		{model.Syn, false},
		{model.Ack, false},
		{model.ARPRequest, false},
	}
	for _, tt := range tests {
		f := flow{flowType: tt.ft}
		if f.isPassive() != tt.want {
			t.Errorf("flowType=%d: isPassive()=%v, want %v", tt.ft, f.isPassive(), tt.want)
		}
	}
}

func TestFlowIsEmpty(t *testing.T) {
	empty := flow{saddr: "0.0.0.0", daddr: "0.0.0.0"}
	if !empty.isEmpty() {
		t.Error("expected zero flow to be empty")
	}

	nonEmpty := flow{saddr: "1.2.3.4", daddr: "0.0.0.0"}
	if nonEmpty.isEmpty() {
		t.Error("expected non-zero saddr flow to not be empty")
	}
}

func TestParseNetworkDiscoveryOutput(t *testing.T) {
	bo := utils.ByteOrder
	if bo == nil {
		bo = binary.LittleEndian
	}

	// Build a 15-flow payload (15 * 32 = 480 bytes)
	buf := make([]byte, 15*32)

	// First flow: 1.2.3.4 -> 5.6.7.8 port 1000 -> 80, IngressFlow, tcp=256
	buf[0], buf[1], buf[2], buf[3] = 1, 2, 3, 4
	buf[4], buf[5], buf[6], buf[7] = 5, 6, 7, 8
	bo.PutUint16(buf[8:10], 1000)
	bo.PutUint16(buf[10:12], 80)
	bo.PutUint32(buf[12:16], uint32(model.IngressFlow))
	bo.PutUint64(buf[16:24], 0)
	bo.PutUint64(buf[24:32], 256)

	// Remaining 14 flows are zero (empty)

	flows, allEmpty := parseNetworkDiscoveryOutput(buf)

	if allEmpty {
		t.Error("expected allEmpty=false with one valid flow")
	}
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].saddr != "1.2.3.4" {
		t.Errorf("saddr=%s, want 1.2.3.4", flows[0].saddr)
	}
	if flows[0].daddr != "5.6.7.8" {
		t.Errorf("daddr=%s, want 5.6.7.8", flows[0].daddr)
	}
	if flows[0].sourcePort != 1000 {
		t.Errorf("sourcePort=%d, want 1000", flows[0].sourcePort)
	}
	if flows[0].destPort != 80 {
		t.Errorf("destPort=%d, want 80", flows[0].destPort)
	}
	if flows[0].tcpCount != 256 {
		t.Errorf("tcpCount=%d, want 256", flows[0].tcpCount)
	}
}

func TestParseNetworkDiscoveryOutputAllEmpty(t *testing.T) {
	buf := make([]byte, 15*32)
	_, allEmpty := parseNetworkDiscoveryOutput(buf)
	if !allEmpty {
		t.Error("expected allEmpty=true for zero buffer")
	}
}
