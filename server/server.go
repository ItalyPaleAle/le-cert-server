package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/yourusername/cert-server/auth"
	"github.com/yourusername/cert-server/certmanager"
)

// Server represents the HTTPS API server
type Server struct {
	manager *certmanager.CertManager
	auth    *auth.Authenticator
	mux     *http.ServeMux
}

// NewServer creates a new API server
func NewServer(manager *certmanager.CertManager, authenticator *auth.Authenticator) *Server {
	s := &Server{
		manager: manager,
		auth:    authenticator,
		mux:     http.NewServeMux(),
	}

	s.registerRoutes()
	return s
}

// registerRoutes sets up the API routes
func (s *Server) registerRoutes() {
	// Health check endpoint (no auth required)
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Protected endpoints
	s.mux.Handle("POST /api/certificate", s.auth.Middleware(http.HandlerFunc(s.handleGetCertificate)))
	s.mux.Handle("POST /api/certificate/renew", s.auth.Middleware(http.HandlerFunc(s.handleRenewCertificate)))
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.mux
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// CertificateRequest represents a certificate request
type CertificateRequest struct {
	Domain string `json:"domain"`
}

// CertificateResponse represents a certificate response
type CertificateResponse struct {
	Domain      string    `json:"domain"`
	Certificate string    `json:"certificate"`
	PrivateKey  string    `json:"private_key"`
	IssuerCert  string    `json:"issuer_cert,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Cached      bool      `json:"cached"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// handleGetCertificate handles certificate retrieval/creation requests
func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
		return
	}

	if req.Domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Domain is required"})
		return
	}

	log.Printf("Certificate request for domain: %s", req.Domain)

	// Try to get or obtain certificate
	cert, err := s.manager.ObtainCertificate(req.Domain)
	if err != nil {
		log.Printf("Failed to obtain certificate for %s: %v", req.Domain, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("Failed to obtain certificate: %v", err)})
		return
	}

	// Check if it was cached (just obtained) or from storage
	cached := time.Since(cert.CreatedAt) > 1*time.Minute

	// Prepare response
	resp := CertificateResponse{
		Domain:      cert.Domain,
		Certificate: string(cert.Certificate),
		PrivateKey:  string(cert.PrivateKey),
		IssuerCert:  string(cert.IssuerCert),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Cached:      cached,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRenewCertificate handles certificate renewal requests
func (s *Server) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req CertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
		return
	}

	if req.Domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Domain is required"})
		return
	}

	log.Printf("Certificate renewal request for domain: %s", req.Domain)

	// Renew certificate
	cert, err := s.manager.RenewCertificate(req.Domain)
	if err != nil {
		log.Printf("Failed to renew certificate for %s: %v", req.Domain, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: fmt.Sprintf("Failed to renew certificate: %v", err)})
		return
	}

	// Prepare response
	resp := CertificateResponse{
		Domain:      cert.Domain,
		Certificate: string(cert.Certificate),
		PrivateKey:  string(cert.PrivateKey),
		IssuerCert:  string(cert.IssuerCert),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Cached:      false,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
