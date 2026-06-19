package stealth

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"net/http"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"curl/8.7.1",
	"curl/8.4.0",
	"python-requests/2.31.0",
	"python-requests/2.32.3",
	"Go-http-client/2.0",
	"axios/1.7.2",
}

type HeaderProfile struct {
	uaPool []string
}

func NewHeaderProfile() *HeaderProfile {
	return &HeaderProfile{
		uaPool: userAgents,
	}
}

func (h *HeaderProfile) ApplyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", h.rotateUA())
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("X-Request-ID", generateRequestID())
}

func (h *HeaderProfile) rotateUA() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(h.uaPool))))
	if err != nil {
		return h.uaPool[0]
	}
	return h.uaPool[n.Int64()]
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
