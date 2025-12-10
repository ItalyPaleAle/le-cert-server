package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	sloghttp "github.com/samber/slog-http"
)

// CertificateRequest represents a certificate request
type CertificateRequest struct {
	Domain string `json:"domain"`
}

// CertificateResponse represents a certificate response
type CertificateResponse struct {
	Domain      string    `json:"domain"`
	Certificate string    `json:"certificate"`
	PrivateKey  string    `json:"privateKey"`
	IssuerCert  string    `json:"issuerCert,omitempty"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Cached      bool      `json:"cached"`
}

// handleGetCertificate handles certificate retrieval/creation requests
func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req CertificateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		errInvalidBody.WriteResponse(w, r)
		return
	}

	if req.Domain == "" {
		errMissingBodyParam.
			Clone(withMetadata(map[string]string{"name": "domain"})).
			WriteResponse(w, r)
		return
	}

	sloghttp.AddCustomAttributes(r, slog.String("domain", req.Domain))

	// Try to get or obtain certificate
	cert, err := s.manager.ObtainCertificate(r.Context(), req.Domain)
	if err != nil {
		slog.Error("Failed to obtain certificate", "domain", req.Domain, "error", err)
		errInternal.WriteResponse(w, r)
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

	w.Header().Set(headerContentType, jsonContentType)
	respondWithJSON(w, r, resp)
}

// handleRenewCertificate handles certificate renewal requests
func (s *Server) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req CertificateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		errInvalidBody.WriteResponse(w, r)
		return
	}

	if req.Domain == "" {
		errMissingBodyParam.
			Clone(withMetadata(map[string]string{"name": "domain"})).
			WriteResponse(w, r)
		return
	}

	sloghttp.AddCustomAttributes(r, slog.String("domain", req.Domain))

	// Renew certificate
	cert, err := s.manager.RenewCertificate(r.Context(), req.Domain)
	if err != nil {
		slog.Error("Failed to renew certificate", "domain", req.Domain, "error", err)
		errInternal.WriteResponse(w, r)
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

	w.Header().Set(headerContentType, jsonContentType)
	respondWithJSON(w, r, resp)
}
