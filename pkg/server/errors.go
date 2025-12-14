package server

import (
	"fmt"
	"net/http"
)

var (
	errInternal         = newApiError("internal", http.StatusInternalServerError, "Internal error")
	errInvalidBody      = newApiError("invalid_body", http.StatusBadRequest, "Invalid request body")
	errMissingBodyParam = newApiError("missing_body_param", http.StatusBadRequest, "Missing required parameter in request body")
	errDomainNotAllowed = newApiError("domain_not_allowed", http.StatusForbidden, "User is not authorized to perform operations on the requested domain")
)

type apiError struct {
	Code       string            `json:"code"`
	Message    string            `json:"message"`
	InnerError error             `json:"innerError,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`

	httpStatus int
}

func newApiError(code string, httpStatus int, message string) *apiError {
	return &apiError{
		Code:    code,
		Message: message,

		httpStatus: httpStatus,
	}
}

func (e apiError) WriteResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Add(headerContentType, jsonContentType)
	w.WriteHeader(e.httpStatus)

	respondWithJSON(w, r, e)
}

// Clone returns a cloned error with the data appended
func (e apiError) Clone(with ...func(*apiError)) *apiError {
	cloned := &apiError{
		Code:    e.Code,
		Message: e.Message,

		httpStatus: e.httpStatus,
	}

	for _, w := range with {
		w(cloned)
	}

	return cloned
}

//nolint:unused
func withInnerError(innerError error) func(*apiError) {
	return func(e *apiError) {
		e.InnerError = innerError
	}
}

//nolint:unused
func withMetadata(metadata map[string]string) func(*apiError) {
	return func(e *apiError) {
		e.Metadata = metadata
	}
}

// Error implements the error interface
func (e apiError) Error() string {
	return fmt.Sprintf("API error (%s): %s", e.Code, e.Message)
}

// Is allows comparing API errors by looking at their status codes
func (e apiError) Is(target error) bool {
	targetApiError, ok := target.(apiError)
	if !ok {
		return false
	}

	return targetApiError.Code == e.Code
}
