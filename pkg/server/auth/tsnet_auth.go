package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
)

// TSNetAuthenticator handles authentication using Tailscale identity
// This authenticator can only be used when the server is running with tsnet listener
type TSNetAuthenticator struct {
	localClient    *local.Client
	allowedTailnet string
}

// NewTSNetAuthenticator creates a new Tailscale identity authenticator
// The localClient is used to query the Tailscale LocalAPI for identity information
func NewTSNetAuthenticator(localClient *local.Client, allowedTailnet string) (*TSNetAuthenticator, error) {
	slog.Info("Initialized Tailscale identity authenticator")

	return &TSNetAuthenticator{
		localClient:    localClient,
		allowedTailnet: allowedTailnet,
	}, nil
}

// Middleware returns an HTTP middleware that validates Tailscale identity
func (a *TSNetAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the remote address from the request
		remoteAddr := r.RemoteAddr
		if remoteAddr == "" {
			slog.Warn("Missing remote address", slog.String("path", r.URL.Path))
			http.Error(w, "Unable to determine remote address", http.StatusUnauthorized)
			return
		}

		// Query Tailscale to get the identity of the remote peer
		whois, err := a.localClient.WhoIs(r.Context(), remoteAddr)
		if err != nil {
			slog.Warn("Failed to get Tailscale identity",
				slog.String("path", r.URL.Path),
				slog.String("remoteAddr", remoteAddr),
				slog.Any("error", err),
			)
			http.Error(w, "Unable to authenticate via Tailscale", http.StatusUnauthorized)
			return
		}

		if a.allowedTailnet != "" {
			// Tailnet of connected node
			// When accessing shared nodes, this will be empty because the Tailnet of the sharee is not exposed
			var tailnet string
			if !whois.Node.Hostinfo.ShareeNode() {
				var ok bool
				_, tailnet, ok = strings.Cut(whois.Node.Name, whois.Node.ComputedName+".")
				if !ok {
					slog.Warn("Failed to extract Tailnet name",
						slog.String("path", r.URL.Path),
						slog.String("remoteAddr", remoteAddr),
						slog.Any("error", fmt.Errorf("failed to extract Tailnet name from hostname '%s'", whois.Node.Name)),
					)
					http.Error(w, "Unable to extract Tailnet name", http.StatusUnauthorized)
					return
				}
				tailnet = strings.TrimSuffix(tailnet, ".beta.tailscale.net")
				tailnet = strings.TrimSuffix(tailnet, ".")
			}

			if tailnet != a.allowedTailnet {
				slog.Warn("User does not belong to allowlisted Tailnet",
					slog.String("path", r.URL.Path),
					slog.String("remoteAddr", remoteAddr),
					slog.String("userTailnet", tailnet),
				)
				http.Error(w, "User's Tailnet is not allowed", http.StatusUnauthorized)
				return
			}
		}

		// Extract user information
		user, err := extractUserFromWhoIs(whois)
		if err != nil {
			slog.Warn("Failed to extract user from Tailscale identity",
				slog.String("path", r.URL.Path),
				slog.String("remoteAddr", remoteAddr),
				slog.Any("error", err),
			)
			http.Error(w, "Unable to extract user identity", http.StatusUnauthorized)
			return
		}

		slog.Debug("Authenticated request via Tailscale",
			slog.String("path", r.URL.Path),
			slog.String("user", user),
			slog.String("remoteAddr", remoteAddr),
		)

		// Add user to context
		ctx := context.WithValue(r.Context(), userContextKey{}, user)

		// Proceed to the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractUserFromWhoIs extracts the user identity from a WhoIsResponse
// Returns the user's login name or email
func extractUserFromWhoIs(whoIs *apitype.WhoIsResponse) (string, error) {
	if whoIs == nil {
		return "", errors.New("whoIs response is nil")
	}

	if whoIs.UserProfile == nil {
		return "", errors.New("user profile is nil")
	}

	// Prefer LoginName if available, fallback to DisplayName
	user := whoIs.UserProfile.LoginName
	if user == "" {
		user = whoIs.UserProfile.DisplayName
	}

	if user == "" {
		return "", errors.New("unable to extract user identity from profile")
	}

	return user, nil
}
