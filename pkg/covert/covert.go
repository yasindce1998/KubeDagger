package covert

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

type Packet struct {
	Data    []byte
	DstAddr string
	DstPort uint16
	Proto   string
}

type Channel interface {
	Name() string
	Encode(data []byte) ([]Packet, error)
	Decode(packets []Packet) ([]byte, error)
	Bandwidth() int
}

type Registry struct {
	mu       sync.RWMutex
	channels map[string]Channel
}

func NewRegistry() *Registry {
	r := &Registry{channels: make(map[string]Channel)}
	r.Register(&ICMPChannel{})
	r.Register(&DNSChannel{})
	r.Register(&TCPRetransmitChannel{})
	r.Register(&TTLChannel{})
	return r
}

func (r *Registry) Register(ch Channel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[ch.Name()] = ch
}

func (r *Registry) Get(name string) (Channel, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ch, ok := r.channels[name]
	if !ok {
		return nil, fmt.Errorf("channel %q not found", name)
	}
	return ch, nil
}

func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.channels))
	for name := range r.channels {
		names = append(names, name)
	}
	return names
}

func generateSequenceID() uint32 {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}
