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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaxMessageSize = 65536
	HeartbeatInterval = 30 * time.Second
	NonceSize      = chacha20poly1305.NonceSize
	TagSize        = chacha20poly1305.Overhead
)

type Server struct {
	key      []byte
	listener net.Listener
	handler  CommandHandler
	mu       sync.Mutex
	clients  map[string]net.Conn
	stop     chan struct{}
}

type CommandHandler func(cmd []byte) ([]byte, error)

func NewServer(key []byte, handler CommandHandler) (*Server, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}
	return &Server{
		key:     key,
		handler: handler,
		clients: make(map[string]net.Conn),
		stop:    make(chan struct{}),
	}, nil
}

func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("c2 listen failed: %w", err)
	}
	s.listener = ln
	logrus.Infof("encrypted C2 listening on %s", addr)

	go s.acceptLoop()
	return nil
}

func (s *Server) Stop() {
	close(s.stop)
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	for _, conn := range s.clients {
		conn.Close()
	}
	s.mu.Unlock()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				logrus.Debugf("accept error: %v", err)
				continue
			}
		}

		remote := conn.RemoteAddr().String()
		s.mu.Lock()
		s.clients[remote] = conn
		s.mu.Unlock()

		go s.handleConn(conn, remote)
	}
}

func (s *Server) handleConn(conn net.Conn, remote string) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.clients, remote)
		s.mu.Unlock()
	}()

	logrus.Infof("c2 client connected: %s", remote)

	for {
		select {
		case <-s.stop:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(HeartbeatInterval * 2))
		msg, err := readEncrypted(conn, s.key)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logrus.Debugf("client %s timed out", remote)
			}
			return
		}

		if len(msg) == 0 {
			continue
		}

		resp, err := s.handler(msg)
		if err != nil {
			logrus.Warnf("handler error for %s: %v", remote, err)
			resp = []byte("ERR:" + err.Error())
		}

		if err := writeEncrypted(conn, s.key, resp); err != nil {
			logrus.Debugf("write error for %s: %v", remote, err)
			return
		}
	}
}

func writeEncrypted(conn net.Conn, key, plaintext []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	totalLen := uint32(NonceSize + len(ciphertext))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, totalLen)

	if _, err := conn.Write(header); err != nil {
		return err
	}
	if _, err := conn.Write(nonce); err != nil {
		return err
	}
	if _, err := conn.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

func readEncrypted(conn net.Conn, key []byte) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	totalLen := binary.BigEndian.Uint32(header)
	if totalLen > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d", totalLen)
	}

	payload := make([]byte, totalLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	if len(payload) < NonceSize {
		return nil, fmt.Errorf("payload too short for nonce")
	}

	nonce := payload[:NonceSize]
	ciphertext := payload[NonceSize:]

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
