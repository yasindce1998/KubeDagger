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

package dashboard

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func pollCmd(target string) tea.Cmd {
	return func() tea.Msg {
		result := pollResultMsg{}

		flows, err := fetchFlows(target)
		if err != nil {
			result.err = err
			return result
		}
		result.flows = flows

		return result
	}
}

func fetchFlows(target string) ([]FlowEntry, error) {
	ua := buildPollUserAgent("0001")
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/get_net_dis", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseFlowData(body), nil
}

func parseFlowData(data []byte) []FlowEntry {
	var flows []FlowEntry
	entrySize := 32
	count := len(data) / entrySize

	for i := 0; i < count; i++ {
		offset := i * entrySize
		if offset+entrySize > len(data) {
			break
		}

		entry := data[offset : offset+entrySize]
		srcIP := net.IPv4(entry[0], entry[1], entry[2], entry[3]).String()
		dstIP := net.IPv4(entry[4], entry[5], entry[6], entry[7]).String()
		srcPort := binary.BigEndian.Uint16(entry[8:10])
		dstPort := binary.BigEndian.Uint16(entry[10:12])
		flowType := binary.LittleEndian.Uint32(entry[12:16])

		if srcIP == "0.0.0.0" && dstIP == "0.0.0.0" {
			break
		}

		proto, typeName := classifyFlow(flowType)

		flows = append(flows, FlowEntry{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
			Proto:   proto,
			Type:    typeName,
		})
	}

	return flows
}

func classifyFlow(flowType uint32) (string, string) {
	switch flowType {
	case 1:
		return "UDP", "passive"
	case 5:
		return "TCP", "passive"
	case 9:
		return "TCP", "SYN"
	case 4:
		return "TCP", "ACK"
	case 6:
		return "ARP", "passive"
	default:
		return "UNK", fmt.Sprintf("%d", flowType)
	}
}

func buildPollUserAgent(id string) string {
	ua := id
	padding := 500 - len(ua)
	if padding > 0 {
		ua += strings.Repeat("_", padding)
	}
	return ua
}
