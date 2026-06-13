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

package c2

import (
	"sync"
)

// TopologyData holds network flow and process info from a single node.
type TopologyData struct {
	NodeAddr  string     `json:"node_addr"`
	Flows     []FlowInfo `json:"flows"`
	Processes []ProcInfo `json:"processes"`
}

type FlowInfo struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   string `json:"proto"`
}

type ProcInfo struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
}

// Topology stores the merged view across all nodes.
type Topology struct {
	mu    sync.RWMutex
	local TopologyData
	nodes map[string]TopologyData
}

func NewTopology() *Topology {
	return &Topology{
		nodes: make(map[string]TopologyData),
	}
}

// UpdateLocal sets the local node's topology data.
func (t *Topology) UpdateLocal(data TopologyData) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.local = data
}

// GetLocal returns the local node's topology.
func (t *Topology) GetLocal() TopologyData {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.local
}

// Merge incorporates a remote node's topology data.
func (t *Topology) Merge(nodeAddr string, data TopologyData) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[nodeAddr] = data
}

// GetMerged returns the combined topology from all known nodes.
func (t *Topology) GetMerged() []TopologyData {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := []TopologyData{t.local}
	for _, n := range t.nodes {
		result = append(result, n)
	}
	return result
}

// GetAllFlows returns all flows from all nodes (local + remote).
func (t *Topology) GetAllFlows() []FlowInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var all []FlowInfo
	all = append(all, t.local.Flows...)
	for _, n := range t.nodes {
		all = append(all, n.Flows...)
	}
	return all
}
