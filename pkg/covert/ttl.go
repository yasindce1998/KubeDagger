package covert

import (
	"fmt"
)

const (
	ttlBaseline    = 64
	ttlBitsPerPkt  = 6
	ttlMaxPayload  = 128
)

type TTLChannel struct {
	dst  string
	port uint16
}

func NewTTLChannel(dst string, port uint16) *TTLChannel {
	return &TTLChannel{dst: dst, port: port}
}

func (c *TTLChannel) Name() string { return "ttl" }

func (c *TTLChannel) Bandwidth() int { return 48 }

func (c *TTLChannel) Encode(data []byte) ([]Packet, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	if len(data) > ttlMaxPayload {
		return nil, fmt.Errorf("payload too large for TTL channel (max %d bytes)", ttlMaxPayload)
	}

	var bits []byte
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1)
		}
	}

	var packets []Packet
	for i := 0; i < len(bits); i += ttlBitsPerPkt {
		end := min(i+ttlBitsPerPkt, len(bits))
		chunk := bits[i:end]

		var encoded byte
		for _, bit := range chunk {
			encoded = (encoded << 1) | bit
		}
		encoded <<= uint(ttlBitsPerPkt - len(chunk))

		ttlValue := ttlBaseline + encoded

		pkt := Packet{
			Data:    []byte{ttlValue, byte(i / ttlBitsPerPkt), byte(len(data))},
			DstAddr: c.dst,
			DstPort: c.port,
			Proto:   "udp",
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}

func (c *TTLChannel) Decode(packets []Packet) ([]byte, error) {
	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets to decode")
	}

	type entry struct {
		seq  int
		bits []byte
	}

	var entries []entry
	var dataLen int
	for _, pkt := range packets {
		if len(pkt.Data) < 3 {
			continue
		}
		ttlVal := pkt.Data[0]
		seq := int(pkt.Data[1])
		dataLen = int(pkt.Data[2])

		encoded := ttlVal - ttlBaseline
		var bits []byte
		for i := ttlBitsPerPkt - 1; i >= 0; i-- {
			bits = append(bits, (encoded>>uint(i))&1)
		}
		entries = append(entries, entry{seq: seq, bits: bits})
	}

	sorted := make([][]byte, len(entries))
	for _, e := range entries {
		if e.seq < len(sorted) {
			sorted[e.seq] = e.bits
		}
	}

	var allBits []byte
	for _, b := range sorted {
		allBits = append(allBits, b...)
	}

	totalBits := dataLen * 8
	if len(allBits) > totalBits {
		allBits = allBits[:totalBits]
	}

	result := make([]byte, dataLen)
	for i := range dataLen {
		if i*8+8 > len(allBits) {
			break
		}
		var b byte
		for j := range 8 {
			b = (b << 1) | allBits[i*8+j]
		}
		result[i] = b
	}

	return result, nil
}
