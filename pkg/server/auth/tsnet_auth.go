package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
	"tailscale.com/tailcfg"

	"github.com/italypaleale/le-cert-server/pkg/buildinfo"
)

var (
	errTSNetNodeIdentity      = httpserver.NewApiError("tsnet_node_identity", http.StatusForbidden, "Could not determine the Tailscale node's identity")
	errTSNetCapabilities      = httpserver.NewApiError("tsnet_invalid_capabilities", http.StatusInternalServerError, "Failed to unmarshal Tailscale node capabilities")
	errTSNetCapabilitiesEmpty = httpserver.NewApiError("tsnet_empty_capabilities", http.StatusForbidden, "Tailscale node capabilities do not include any domains")
)

// TSNetAuthenticator handles authentication using Tailscale identity
// This authenticator can only be used when the server is running with tsnet listener
type TSNetAuthenticator struct {
	srv *tsnetserver.TSNetServer
}

type tsCapRule struct {
	Domains []string `json:"domains"`
}

type tsCapRuleList []tsCapRule

func (l tsCapRuleList) AllDomains() []string {
	var size, i int
	for _, e := range l {
		size += len(e.Domains)
	}

	res := make([]string, size)
	for _, e := range l {
		for _, d := range e.Domains {
			res[i] = d
			i++
		}
	}

	return res
}

// NewTSNetAuthenticator creates a new Tailscale identity authenticator
// The localClient is used to query the Tailscale LocalAPI for identity information
func NewTSNetAuthenticator(tsnetServer *tsnetserver.TSNetServer) (*TSNetAuthenticator, error) {
	slog.Info("Initialized Tailscale identity authenticator")

	return &TSNetAuthenticator{
		srv: tsnetServer,
	}, nil
}

// Middleware returns an HTTP middleware that validates Tailscale identity
func (a *TSNetAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get Tailscale connection info from tsnet
		whois, err := a.srv.WhoIs(r)
		if err != nil {
			slog.WarnContext(r.Context(), "Failed to get Tailscale identity", slog.Any("error", err))
			errTSNetNodeIdentity.WriteResponse(w, r)
			return
		}

		// Get the capabilities assigned to the user
		rules, err := tailcfg.UnmarshalCapJSON[tsCapRule](whois.CapMap, buildinfo.AppNamespace)
		if err != nil {
			slog.WarnContext(r.Context(), "Failed to get Tailscale capabilities", slog.Any("error", err))
			errTSNetCapabilities.WriteResponse(w, r)
			return
		}

		domains := tsCapRuleList(rules).AllDomains()
		if len(domains) == 0 {
			errTSNetCapabilitiesEmpty.WriteResponse(w, r)
			return
		}

		// Extract user information
		slog.Debug("Authenticated request via Tailscale",
			slog.String("path", r.URL.Path),
			slog.String("node", whois.Name),
		)

		// Add user and domains to context
		ctx := context.WithValue(r.Context(), userContextKey{}, whois.Name)
		ctx = context.WithValue(ctx, domainsContextKey{}, domains)

		// Proceed to the next handler with the updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
