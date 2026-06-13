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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

// Client connects to the encrypted C2 server.
type Client struct {
	key  []byte
	conn net.Conn
	stop chan struct{}
}

func NewClient(key []byte) (*Client, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}
	return &Client{
		key:  key,
		stop: make(chan struct{}),
	}, nil
}

func (c *Client) Connect(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("c2 connect failed: %w", err)
	}
	c.conn = conn
	go c.heartbeatLoop()
	return nil
}

func (c *Client) Close() {
	close(c.stop)
	if c.conn != nil {
		c.conn.Close()
	}
}

// SendCommand sends an encrypted command and reads the encrypted response.
func (c *Client) SendCommand(cmd []byte) ([]byte, error) {
	if err := writeEncrypted(c.conn, c.key, cmd); err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := readEncrypted(c.conn, c.key)
	if err != nil {
		return nil, fmt.Errorf("recv failed: %w", err)
	}

	return resp, nil
}

func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			if err := writeEncrypted(c.conn, c.key, nil); err != nil {
				logrus.Debugf("heartbeat failed: %v", err)
				return
			}
		}
	}
}

// DeriveKey generates a 32-byte key from a hex-encoded passphrase.
// If the input is less than 32 bytes, it is zero-padded.
// If it's a valid 64-char hex string, it's decoded directly.
func DeriveKey(input string) ([]byte, error) {
	if len(input) == 64 {
		key, err := hex.DecodeString(input)
		if err == nil && len(key) == chacha20poly1305.KeySize {
			return key, nil
		}
	}

	key := make([]byte, chacha20poly1305.KeySize)
	copy(key, []byte(input))
	return key, nil
}

// GenerateKey creates a new random 32-byte key and returns it hex-encoded.
func GenerateKey() (string, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
