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
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	PeerHeartbeatInterval = 30 * time.Second
	PeerTimeout           = 90 * time.Second
	TopologySyncInterval  = 60 * time.Second
)

type PeerState struct {
	Address  string    `json:"address"`
	NodeName string    `json:"node_name"`
	LastSeen time.Time `json:"last_seen"`
	Alive    bool      `json:"alive"`
}

type PeerManager struct {
	key     []byte
	self    string
	mu      sync.RWMutex
	peers   map[string]*PeerState
	topo    *Topology
	stop    chan struct{}
}

func NewPeerManager(key []byte, selfAddr string) *PeerManager {
	return &PeerManager{
		key:   key,
		self:  selfAddr,
		peers: make(map[string]*PeerState),
		topo:  NewTopology(),
		stop:  make(chan struct{}),
	}
}

// AddPeer registers a remote peer address.
func (pm *PeerManager) AddPeer(addr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.peers[addr] = &PeerState{
		Address: addr,
		Alive:   false,
	}
}

// Start begins the heartbeat and topology sync loops.
func (pm *PeerManager) Start() {
	go pm.heartbeatLoop()
	go pm.topologySyncLoop()
}

func (pm *PeerManager) Stop() {
	close(pm.stop)
}

// GetTopology returns the merged topology from all peers.
func (pm *PeerManager) GetTopology() *Topology {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.topo
}

// GetPeers returns current peer state.
func (pm *PeerManager) GetPeers() []PeerState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var result []PeerState
	for _, p := range pm.peers {
		result = append(result, *p)
	}
	return result
}

func (pm *PeerManager) heartbeatLoop() {
	ticker := time.NewTicker(PeerHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stop:
			return
		case <-ticker.C:
			pm.sendHeartbeats()
			pm.expireStale()
		}
	}
}

func (pm *PeerManager) sendHeartbeats() {
	pm.mu.RLock()
	addrs := make([]string, 0, len(pm.peers))
	for addr := range pm.peers {
		addrs = append(addrs, addr)
	}
	pm.mu.RUnlock()

	hb := HeartbeatMsg{
		From:     pm.self,
		NodeName: hostname(),
		Time:     time.Now(),
	}
	data, _ := json.Marshal(hb)

	for _, addr := range addrs {
		go pm.sendToPeer(addr, append([]byte("HB:"), data...))
	}
}

func (pm *PeerManager) sendToPeer(addr string, msg []byte) {
	client, err := NewClient(pm.key)
	if err != nil {
		return
	}
	if err := client.Connect(addr); err != nil {
		logrus.Debugf("peer %s unreachable: %v", addr, err)
		pm.markDead(addr)
		return
	}
	defer client.Close()

	resp, err := client.SendCommand(msg)
	if err != nil {
		pm.markDead(addr)
		return
	}

	pm.mu.Lock()
	if p, ok := pm.peers[addr]; ok {
		p.LastSeen = time.Now()
		p.Alive = true
	}
	pm.mu.Unlock()

	pm.handlePeerResponse(addr, resp)
}

func (pm *PeerManager) handlePeerResponse(addr string, resp []byte) {
	if len(resp) < 3 {
		return
	}

	switch string(resp[:3]) {
	case "TP:":
		var remote TopologyData
		if err := json.Unmarshal(resp[3:], &remote); err == nil {
			pm.topo.Merge(addr, remote)
		}
	}
}

func (pm *PeerManager) topologySyncLoop() {
	ticker := time.NewTicker(TopologySyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stop:
			return
		case <-ticker.C:
			pm.syncTopology()
		}
	}
}

func (pm *PeerManager) syncTopology() {
	local := pm.topo.GetLocal()
	data, _ := json.Marshal(local)
	msg := append([]byte("TS:"), data...)

	pm.mu.RLock()
	addrs := make([]string, 0, len(pm.peers))
	for addr, p := range pm.peers {
		if p.Alive {
			addrs = append(addrs, addr)
		}
	}
	pm.mu.RUnlock()

	for _, addr := range addrs {
		go pm.sendToPeer(addr, msg)
	}
}

func (pm *PeerManager) markDead(addr string) {
	pm.mu.Lock()
	if p, ok := pm.peers[addr]; ok {
		p.Alive = false
	}
	pm.mu.Unlock()
}

func (pm *PeerManager) expireStale() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	now := time.Now()
	for _, p := range pm.peers {
		if p.Alive && now.Sub(p.LastSeen) > PeerTimeout {
			p.Alive = false
			logrus.Infof("peer %s timed out", p.Address)
		}
	}
}

func hostname() string {
	// Simplistic; overridden by node name from k8s if available
	return fmt.Sprintf("node-%d", time.Now().UnixNano()%1000)
}

type HeartbeatMsg struct {
	From     string    `json:"from"`
	NodeName string    `json:"node_name"`
	Time     time.Time `json:"time"`
}
