package covert

import (
	"encoding/binary"
	"fmt"
)

const (
	tcpRetransmitMaxPayload = 32
	tcpFlagACK              = 0x10
	tcpFlagPSH              = 0x08
)

type TCPRetransmitChannel struct {
	dst  string
	port uint16
}

func NewTCPRetransmitChannel(dst string, port uint16) *TCPRetransmitChannel {
	return &TCPRetransmitChannel{dst: dst, port: port}
}

func (c *TCPRetransmitChannel) Name() string { return "tcp_retransmit" }

func (c *TCPRetransmitChannel) Bandwidth() int { return 256 }

func (c *TCPRetransmitChannel) Encode(data []byte) ([]Packet, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	seqID := generateSequenceID()
	totalChunks := (len(data) + tcpRetransmitMaxPayload - 1) / tcpRetransmitMaxPayload

	var packets []Packet
	seq := seqID

	for i := range totalChunks {
		start := i * tcpRetransmitMaxPayload
		end := min(start+tcpRetransmitMaxPayload, len(data))
		chunk := data[start:end]

		payload := make([]byte, 0, 20+len(chunk))
		header := make([]byte, 20)
		binary.BigEndian.PutUint16(header[0:2], 0xC000|uint16(i&0x3FFF))
		binary.BigEndian.PutUint16(header[2:4], c.port)
		binary.BigEndian.PutUint32(header[4:8], seq)
		binary.BigEndian.PutUint32(header[8:12], 0)
		header[12] = 5 << 4
		header[13] = tcpFlagACK | tcpFlagPSH
		binary.BigEndian.PutUint16(header[14:16], 65535)
		binary.BigEndian.PutUint16(header[18:20], uint16(totalChunks))

		payload = append(payload, header...)
		payload = append(payload, chunk...)

		packets = append(packets, Packet{
			Data:    payload,
			DstAddr: c.dst,
			DstPort: c.port,
			Proto:   "tcp",
		})

		seq += uint32(len(chunk))
	}

	return packets, nil
}

func (c *TCPRetransmitChannel) Decode(packets []Packet) ([]byte, error) {
	if len(packets) == 0 {
		return nil, fmt.Errorf("no packets to decode")
	}

	type fragment struct {
		idx  int
		data []byte
	}

	var fragments []fragment
	for _, pkt := range packets {
		if len(pkt.Data) < 20 {
			continue
		}
		srcPort := binary.BigEndian.Uint16(pkt.Data[0:2])
		idx := int(srcPort & 0x3FFF)
		payload := pkt.Data[20:]
		fragments = append(fragments, fragment{idx: idx, data: payload})
	}

	sorted := make([][]byte, len(fragments))
	for _, f := range fragments {
		if f.idx < len(sorted) {
			sorted[f.idx] = f.data
		}
	}

	var result []byte
	for _, d := range sorted {
		result = append(result, d...)
	}
	return result, nil
}
