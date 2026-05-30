package server

import (
	"net/http"

	httpserver "github.com/italypaleale/go-kit/httpserver"
)

var (
	errInternal         = httpserver.NewApiError("internal", http.StatusInternalServerError, "Internal error")
	errInvalidBody      = httpserver.NewApiError("invalid_body", http.StatusBadRequest, "Invalid request body")
	errMissingBodyParam = httpserver.NewApiError("missing_body_param", http.StatusBadRequest, "Missing required parameter in request body")
	errDomainNotAllowed = httpserver.NewApiError("domain_not_allowed", http.StatusForbidden, "User is not authorized to perform operations on the requested domain")
	errRenewTooSoon     = httpserver.NewApiError("renew_too_soon", http.StatusTooManyRequests, "Certificate is not yet due for renewal")
)
