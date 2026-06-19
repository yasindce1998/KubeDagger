package multicluster

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ClusterRoute represents a path to reach a specific cluster through relay nodes.
type ClusterRoute struct {
	ClusterID  string
	Endpoint   string
	RelayChain []string
	Priority   int
	Healthy    bool
}

// RouteTable maintains routing state for multi-cluster agent communication.
type RouteTable struct {
	mu     sync.RWMutex
	routes map[string]*ClusterRoute
}

// NewRouteTable creates an empty route table.
func NewRouteTable() *RouteTable {
	return &RouteTable{
		routes: make(map[string]*ClusterRoute),
	}
}

func (rt *RouteTable) AddRoute(route *ClusterRoute) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes[route.ClusterID] = route
}

func (rt *RouteTable) RemoveRoute(clusterID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.routes, clusterID)
}

func (rt *RouteTable) GetRoute(clusterID string) (*ClusterRoute, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	r, ok := rt.routes[clusterID]
	return r, ok
}

func (rt *RouteTable) ListRoutes() []ClusterRoute {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	routes := make([]ClusterRoute, 0, len(rt.routes))
	for _, r := range rt.routes {
		routes = append(routes, *r)
	}

	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Priority > routes[j].Priority
	})

	return routes
}

func (rt *RouteTable) HealthyRoutes() []ClusterRoute {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var routes []ClusterRoute
	for _, r := range rt.routes {
		if r.Healthy {
			routes = append(routes, *r)
		}
	}

	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Priority > routes[j].Priority
	})

	return routes
}

func (rt *RouteTable) SetHealth(clusterID string, healthy bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if r, ok := rt.routes[clusterID]; ok {
		r.Healthy = healthy
	}
}

// BuildRouteTable creates a route table from discovered cluster information.
func BuildRouteTable(clusters []ClusterInfo) *RouteTable {
	rt := NewRouteTable()

	for i, cluster := range clusters {
		route := &ClusterRoute{
			ClusterID: GenerateClusterID(cluster),
			Endpoint:  cluster.Server,
			Priority:  len(clusters) - i,
			Healthy:   true,
		}
		rt.AddRoute(route)
	}

	return rt
}

// BuildRelayChain computes the relay path between source and destination clusters.
func BuildRelayChain(rt *RouteTable, src, dst string) []string {
	srcRoute, srcOK := rt.GetRoute(src)
	dstRoute, dstOK := rt.GetRoute(dst)
	if !srcOK || !dstOK {
		return nil
	}

	routes := rt.HealthyRoutes()
	if len(routes) <= 2 {
		return []string{srcRoute.Endpoint, dstRoute.Endpoint}
	}

	chain := []string{srcRoute.Endpoint}
	for _, r := range routes {
		if r.ClusterID != src && r.ClusterID != dst && r.Healthy {
			chain = append(chain, r.Endpoint)
			break
		}
	}
	chain = append(chain, dstRoute.Endpoint)

	return chain
}

// GenerateClusterID produces a deterministic short hash ID from cluster connection details.
func GenerateClusterID(cluster ClusterInfo) string {
	h := sha256.New()
	h.Write([]byte(cluster.Server))
	h.Write([]byte(cluster.Name))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// FormatRouteTable returns a human-readable summary of all routes and their health status.
func FormatRouteTable(rt *RouteTable) string {
	routes := rt.ListRoutes()
	if len(routes) == 0 {
		return "no routes configured"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Routes (%d clusters):\n", len(routes))

	for _, r := range routes {
		status := "UP"
		if !r.Healthy {
			status = "DOWN"
		}
		relay := "direct"
		if len(r.RelayChain) > 0 {
			relay = strings.Join(r.RelayChain, " → ")
		}
		fmt.Fprintf(&sb, "  [%s] %s → %s (priority=%d, path=%s)\n",
			status, r.ClusterID, r.Endpoint, r.Priority, relay)
	}

	return sb.String()
}
