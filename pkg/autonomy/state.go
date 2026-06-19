package autonomy

import (
	"maps"
	"sync"
)

type WorldState struct {
	mu     sync.RWMutex
	facts  map[string]string
	assets []Asset
	caps   map[string]bool
}

type Asset struct {
	Type  string
	ID    string
	Props map[string]string
}

func NewWorldState() *WorldState {
	return &WorldState{
		facts:  make(map[string]string),
		assets: make([]Asset, 0),
		caps:   make(map[string]bool),
	}
}

func (ws *WorldState) SetFact(key, value string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.facts[key] = value
}

func (ws *WorldState) GetFact(key string) (string, bool) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	v, ok := ws.facts[key]
	return v, ok
}

func (ws *WorldState) HasFact(key string) bool {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	_, ok := ws.facts[key]
	return ok
}

func (ws *WorldState) AddAsset(a Asset) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.assets = append(ws.assets, a)
}

func (ws *WorldState) GetAssets(assetType string) []Asset {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	var result []Asset
	for _, a := range ws.assets {
		if a.Type == assetType {
			result = append(result, a)
		}
	}
	return result
}

func (ws *WorldState) AddCapability(cap string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.caps[cap] = true
}

func (ws *WorldState) HasCapability(cap string) bool {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	return ws.caps[cap]
}

func (ws *WorldState) AllFacts() map[string]string {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	result := make(map[string]string, len(ws.facts))
	maps.Copy(result, ws.facts)
	return result
}
