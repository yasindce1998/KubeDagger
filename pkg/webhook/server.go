package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Server struct {
	certPEM  []byte
	keyPEM   []byte
	image    string
	targetNS string
	server   *http.Server
	mutator  *Mutator
}

type Config struct {
	Image    string
	TargetNS string
	Port     int
}

func NewServer(certPEM, keyPEM []byte, cfg Config) *Server {
	s := &Server{
		certPEM:  certPEM,
		keyPEM:   keyPEM,
		image:    cfg.Image,
		targetNS: cfg.TargetNS,
		mutator:  NewMutator(cfg.Image),
	}
	return s
}

func (s *Server) Start(port int) error {
	cert, err := tls.X509KeyPair(s.certPEM, s.keyPEM)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.handleAdmission)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s.server = &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Handler: mux,
	}

	return s.server.ListenAndServeTLS("", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleAdmission(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "unmarshal review", http.StatusBadRequest)
		return
	}

	response := s.mutator.Mutate(review.Request)

	review.Response = response
	review.Response.UID = review.Request.UID

	respBytes, err := json.Marshal(review)
	if err != nil {
		http.Error(w, "marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBytes)
}

func allowResponse() *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Result: &metav1.Status{
			Status: "Success",
		},
	}
}
