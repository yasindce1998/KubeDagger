package covert

import (
	"encoding/binary"
	"fmt"
)

const (
	icmpMaxPayload = 56
	icmpHeaderSize = 8
	icmpTypeEcho   = 8
)

type ICMPChannel struct {
	dst string
}

func NewICMPChannel(dst string) *ICMPChannel {
	return &ICMPChannel{dst: dst}
}

func (c *ICMPChannel) Name() string { return "icmp" }

func (c *ICMPChannel) Bandwidth() int { return 448 }

func (c *ICMPChannel) Encode(data []byte) ([]Packet, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	seqID := generateSequenceID()
	totalChunks := (len(data) + icmpMaxPayload - 5) / (icmpMaxPayload - 4)

	var packets []Packet
	offset := 0
	for i := range totalChunks {
		end := min(offset+icmpMaxPayload-4, len(data))

		chunk := data[offset:end]
		payload := make([]byte, 0, icmpHeaderSize+4+len(chunk))

		header := make([]byte, icmpHeaderSize)
		header[0] = icmpTypeEcho
		header[1] = 0
		binary.BigEndian.PutUint16(header[4:6], uint16(seqID>>16))
		binary.BigEndian.PutUint16(header[6:8], uint16(i))
		payload = append(payload, header...)

		meta := make([]byte, 4)
		binary.BigEndian.PutUint16(meta[0:2], uint16(totalChunks))
		binary.BigEndian.PutUint16(meta[2:4], uint16(len(chunk)))
		payload = append(payload, meta...)
		payload = append(payload, chunk...)

		cs := icmpChecksum(payload)
		binary.BigEndian.PutUint16(payload[2:4], cs)

		packets = append(packets, Packet{
			Data:    payload,
			DstAddr: c.dst,
			Proto:   "icmp",
		})
		offset = end
	}
	return packets, nil
}

func (c *ICMPChannel) Decode(packets []Packet) ([]byte, error) {
	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets to decode")
	}

	type chunk struct {
		seq  int
		data []byte
	}

	var chunks []chunk
	for _, pkt := range packets {
		if len(pkt.Data) < icmpHeaderSize+4 {
			continue
		}
		seq := int(binary.BigEndian.Uint16(pkt.Data[6:8]))
		chunkLen := int(binary.BigEndian.Uint16(pkt.Data[icmpHeaderSize+2 : icmpHeaderSize+4]))
		dataStart := icmpHeaderSize + 4
		if dataStart+chunkLen > len(pkt.Data) {
			chunkLen = len(pkt.Data) - dataStart
		}
		chunks = append(chunks, chunk{seq: seq, data: pkt.Data[dataStart : dataStart+chunkLen]})
	}

	sorted := make([][]byte, len(chunks))
	for _, ch := range chunks {
		if ch.seq < len(sorted) {
			sorted[ch.seq] = ch.data
		}
	}

	var result []byte
	for _, d := range sorted {
		result = append(result, d...)
	}
	return result, nil
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
