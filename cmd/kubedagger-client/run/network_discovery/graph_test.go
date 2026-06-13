package network_discovery

import (
	"testing"
)

func TestGenerateNodeID(t *testing.T) {
	id1 := generateNodeID("192.168.1.1:80")
	id2 := generateNodeID("192.168.1.1:80")
	id3 := generateNodeID("10.0.0.1:443")

	if id1 != id2 {
		t.Errorf("same input produced different IDs: %s vs %s", id1, id2)
	}
	if id1 == id3 {
		t.Errorf("different inputs produced same ID: %s", id1)
	}
	if len(id1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(id1))
	}
}

func TestPrepareGraphData(t *testing.T) {
	flows := []flow{
		{
			saddr:      "192.168.1.1",
			daddr:      "10.0.0.1",
			sourcePort: 12345,
			destPort:   80,
			flowType:   1,
			udpCount:   0,
			tcpCount:   1024,
		},
		{
			saddr:      "192.168.1.1",
			daddr:      "10.0.0.2",
			sourcePort: 12346,
			destPort:   443,
			flowType:   2,
			udpCount:   512,
			tcpCount:   0,
		},
	}

	data := prepareGraphData("test", flows, true, true)

	if data.Title != "test" {
		t.Errorf("expected title 'test', got %q", data.Title)
	}
	if len(data.Hosts) == 0 {
		t.Error("expected at least one host cluster")
	}
	if len(data.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(data.Edges))
	}
}
