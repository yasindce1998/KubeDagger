package multicluster

import (
	"strings"
	"testing"
)

func TestNewRouteTable(t *testing.T) {
	rt := NewRouteTable()
	if rt == nil {
		t.Fatal("NewRouteTable returned nil")
	}
	if routes := rt.ListRoutes(); len(routes) != 0 {
		t.Fatalf("expected empty route table, got %d routes", len(routes))
	}
}

func TestAddAndGetRoute(t *testing.T) {
	rt := NewRouteTable()
	route := &ClusterRoute{
		ClusterID: "abc123",
		Endpoint:  "https://cluster-a:6443",
		Priority:  10,
		Healthy:   true,
	}

	rt.AddRoute(route)

	got, ok := rt.GetRoute("abc123")
	if !ok {
		t.Fatal("GetRoute returned false for existing route")
	}
	if got.Endpoint != "https://cluster-a:6443" {
		t.Errorf("got endpoint %q, want %q", got.Endpoint, "https://cluster-a:6443")
	}
	if got.Priority != 10 {
		t.Errorf("got priority %d, want 10", got.Priority)
	}
}

func TestGetRouteNotFound(t *testing.T) {
	rt := NewRouteTable()
	_, ok := rt.GetRoute("nonexistent")
	if ok {
		t.Fatal("GetRoute returned true for nonexistent route")
	}
}

func TestRemoveRoute(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(&ClusterRoute{ClusterID: "abc123", Endpoint: "https://a:6443", Priority: 1, Healthy: true})
	rt.AddRoute(&ClusterRoute{ClusterID: "def456", Endpoint: "https://b:6443", Priority: 2, Healthy: true})

	rt.RemoveRoute("abc123")

	_, ok := rt.GetRoute("abc123")
	if ok {
		t.Fatal("route not removed")
	}
	_, ok = rt.GetRoute("def456")
	if !ok {
		t.Fatal("wrong route removed")
	}
}

func TestListRoutesSortedByPriority(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(&ClusterRoute{ClusterID: "low", Endpoint: "https://low:6443", Priority: 1, Healthy: true})
	rt.AddRoute(&ClusterRoute{ClusterID: "high", Endpoint: "https://high:6443", Priority: 10, Healthy: true})
	rt.AddRoute(&ClusterRoute{ClusterID: "mid", Endpoint: "https://mid:6443", Priority: 5, Healthy: true})

	routes := rt.ListRoutes()
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0].ClusterID != "high" {
		t.Errorf("first route should be highest priority, got %q", routes[0].ClusterID)
	}
	if routes[1].ClusterID != "mid" {
		t.Errorf("second route should be mid priority, got %q", routes[1].ClusterID)
	}
	if routes[2].ClusterID != "low" {
		t.Errorf("third route should be lowest priority, got %q", routes[2].ClusterID)
	}
}

func TestHealthyRoutes(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(&ClusterRoute{ClusterID: "a", Endpoint: "https://a:6443", Priority: 3, Healthy: true})
	rt.AddRoute(&ClusterRoute{ClusterID: "b", Endpoint: "https://b:6443", Priority: 2, Healthy: false})
	rt.AddRoute(&ClusterRoute{ClusterID: "c", Endpoint: "https://c:6443", Priority: 1, Healthy: true})

	healthy := rt.HealthyRoutes()
	if len(healthy) != 2 {
		t.Fatalf("expected 2 healthy routes, got %d", len(healthy))
	}
	for _, r := range healthy {
		if r.ClusterID == "b" {
			t.Error("unhealthy route included in HealthyRoutes")
		}
	}
}

func TestSetHealth(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(&ClusterRoute{ClusterID: "a", Endpoint: "https://a:6443", Priority: 1, Healthy: true})

	rt.SetHealth("a", false)
	r, _ := rt.GetRoute("a")
	if r.Healthy {
		t.Error("SetHealth(false) did not update route")
	}

	rt.SetHealth("a", true)
	r, _ = rt.GetRoute("a")
	if !r.Healthy {
		t.Error("SetHealth(true) did not update route")
	}

	// SetHealth on nonexistent route should not panic
	rt.SetHealth("nonexistent", true)
}

func TestGenerateClusterID(t *testing.T) {
	cluster := ClusterInfo{Name: "prod", Server: "https://prod.example.com:6443"}
	id := GenerateClusterID(cluster)

	if len(id) != 12 {
		t.Errorf("expected 12-char ID, got %d chars: %q", len(id), id)
	}

	// Deterministic
	id2 := GenerateClusterID(cluster)
	if id != id2 {
		t.Error("GenerateClusterID is not deterministic")
	}

	// Different input produces different ID
	other := ClusterInfo{Name: "staging", Server: "https://staging.example.com:6443"}
	otherId := GenerateClusterID(other)
	if id == otherId {
		t.Error("different clusters produced same ID")
	}
}

func TestBuildRouteTable(t *testing.T) {
	clusters := []ClusterInfo{
		{Name: "cluster-a", Server: "https://a:6443"},
		{Name: "cluster-b", Server: "https://b:6443"},
		{Name: "cluster-c", Server: "https://c:6443"},
	}

	rt := BuildRouteTable(clusters)
	routes := rt.ListRoutes()

	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}

	// First cluster should have highest priority
	idA := GenerateClusterID(clusters[0])
	rA, ok := rt.GetRoute(idA)
	if !ok {
		t.Fatal("first cluster route not found")
	}
	if rA.Priority != 3 {
		t.Errorf("first cluster priority = %d, want 3", rA.Priority)
	}
	if !rA.Healthy {
		t.Error("newly built route should be healthy")
	}
}

func TestBuildRelayChainDirect(t *testing.T) {
	clusters := []ClusterInfo{
		{Name: "src", Server: "https://src:6443"},
		{Name: "dst", Server: "https://dst:6443"},
	}
	rt := BuildRouteTable(clusters)

	srcID := GenerateClusterID(clusters[0])
	dstID := GenerateClusterID(clusters[1])

	chain := BuildRelayChain(rt, srcID, dstID)
	if len(chain) != 2 {
		t.Fatalf("expected 2-hop direct chain, got %d", len(chain))
	}
	if chain[0] != "https://src:6443" || chain[1] != "https://dst:6443" {
		t.Errorf("unexpected chain: %v", chain)
	}
}

func TestBuildRelayChainWithRelay(t *testing.T) {
	clusters := []ClusterInfo{
		{Name: "src", Server: "https://src:6443"},
		{Name: "relay", Server: "https://relay:6443"},
		{Name: "dst", Server: "https://dst:6443"},
	}
	rt := BuildRouteTable(clusters)

	srcID := GenerateClusterID(clusters[0])
	dstID := GenerateClusterID(clusters[2])

	chain := BuildRelayChain(rt, srcID, dstID)
	if len(chain) != 3 {
		t.Fatalf("expected 3-hop chain, got %d", len(chain))
	}
	if chain[0] != "https://src:6443" {
		t.Errorf("chain[0] = %q, want src", chain[0])
	}
	if chain[2] != "https://dst:6443" {
		t.Errorf("chain[2] = %q, want dst", chain[2])
	}
}

func TestBuildRelayChainInvalidIDs(t *testing.T) {
	rt := NewRouteTable()
	chain := BuildRelayChain(rt, "bad-src", "bad-dst")
	if chain != nil {
		t.Errorf("expected nil chain for invalid IDs, got %v", chain)
	}
}

func TestFormatRouteTableEmpty(t *testing.T) {
	rt := NewRouteTable()
	out := FormatRouteTable(rt)
	if out != "no routes configured" {
		t.Errorf("unexpected output for empty table: %q", out)
	}
}

func TestFormatRouteTableNonEmpty(t *testing.T) {
	rt := NewRouteTable()
	rt.AddRoute(&ClusterRoute{ClusterID: "abc123", Endpoint: "https://a:6443", Priority: 5, Healthy: true})
	rt.AddRoute(&ClusterRoute{ClusterID: "def456", Endpoint: "https://b:6443", Priority: 3, Healthy: false})

	out := FormatRouteTable(rt)
	if !strings.Contains(out, "2 clusters") {
		t.Errorf("output missing cluster count: %q", out)
	}
	if !strings.Contains(out, "UP") {
		t.Error("output missing UP status")
	}
	if !strings.Contains(out, "DOWN") {
		t.Error("output missing DOWN status")
	}
}
