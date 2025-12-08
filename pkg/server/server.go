package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	sloghttp "github.com/samber/slog-http"

	"github.com/italypaleale/le-cert-server/pkg/auth"
	"github.com/italypaleale/le-cert-server/pkg/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/utils"
)

const (
	headerContentType = "Content-Type"
	jsonContentType   = "application/json; charset=utf-8"
)

// Server is the server based on Gin
type Server struct {
	appSrv  *http.Server
	handler http.Handler
	running atomic.Bool
	wg      sync.WaitGroup

	appMetrics *metrics.AppMetrics
	manager    *certmanager.CertManager
	auth       auth.Authenticator

	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn

	// TLS configuration for the app server
	tlsConfig *tls.Config

	// Listener for the app server
	// This can be used for testing without having to start an actual TCP listener
	appListener net.Listener
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	AppMetrics    *metrics.AppMetrics
	Manager       *certmanager.CertManager
	Authenticator auth.Authenticator
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (*Server, error) {
	s := &Server{
		appMetrics: opts.AppMetrics,
		manager:    opts.Manager,
		auth:       opts.Authenticator,
	}

	// Init the object
	err := s.init()
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Init the Server object and create the mux
func (s *Server) init() error {
	// Init the app server
	err := s.initAppServer()
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initAppServer() (err error) {
	// Load the TLS configuration
	s.tlsConfig, s.tlsCertWatchFn, err = s.loadTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	// Create the mux
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("POST /api/certificate", s.auth.Middleware(http.HandlerFunc(s.handleGetCertificate)))
	mux.Handle("POST /api/certificate/renew", s.auth.Middleware(http.HandlerFunc(s.handleRenewCertificate)))

	middlewares := make([]Middleware, 0, 4)
	middlewares = append(middlewares,
		// Recover from panics
		sloghttp.Recovery,
		// Limit request body to 1KB
		MiddlewareMaxBodySize(1<<10),
	)

	middlewares = append(middlewares,
		// Log requests
		sloghttp.New(slog.Default()),
	)

	// Add middlewares
	s.handler = Use(mux, middlewares...)

	return nil
}

// Run the web server
// Note this function is blocking, and will return only when the server is shut down via context cancellation.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("server is already running")
	}
	defer s.running.Store(false)
	defer s.wg.Wait()

	// App server
	s.wg.Add(1)
	err := s.startAppServer(ctx)
	if err != nil {
		return fmt.Errorf("failed to start app server: %w", err)
	}
	defer func() { //nolint:contextcheck
		// Handle graceful shutdown
		defer s.wg.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.appSrv.Shutdown(shutdownCtx)
		shutdownCancel()
		if err != nil {
			// Log the error only (could be context canceled)
			slog.WarnContext(shutdownCtx,
				"App server shutdown error",
				slog.Any("error", err),
			)
		}
	}()

	// If we have a tlsCertWatchFn, invoke that
	if s.tlsCertWatchFn != nil {
		err = s.tlsCertWatchFn(ctx)
		if err != nil {
			return fmt.Errorf("failed to watch for TLS certificates: %w", err)
		}
	}

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) startAppServer(ctx context.Context) error {
	cfg := config.Get()

	// Create the HTTP(S) server
	s.appSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Bind, strconv.Itoa(cfg.Server.Port)),
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           s.handler,
	}

	if s.tlsConfig == nil {
		// Not using TLS
		slog.WarnContext(ctx, "Starting app server without TLS - this is not recommended unless the app is exposed through a proxy that offers TLS termination")
	} else {
		// Using TLS
		s.appSrv.TLSConfig = s.tlsConfig
	}

	// Create the listener if we don't have one already
	if s.appListener == nil {
		var err error
		s.appListener, err = net.Listen("tcp", s.appSrv.Addr) //nolint:noctx
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTP(S) server in a background goroutine
	slog.InfoContext(ctx, "App server started",
		slog.String("bind", cfg.Server.Bind),
		slog.Int("port", cfg.Server.Port),
		slog.Bool("tls", s.tlsConfig != nil),
	)
	go func() { //nolint:contextcheck
		defer s.appListener.Close() //nolint:errcheck

		// Next call blocks until the server is shut down
		var srvErr error
		if s.tlsConfig != nil {
			srvErr = s.appSrv.ServeTLS(s.appListener, "", "")
		} else {
			srvErr = s.appSrv.Serve(s.appListener)
		}
		if !errors.Is(srvErr, http.ErrServerClosed) {
			utils.FatalError(slog.Default(), "Error starting app server", srvErr)
		}
	}()

	return nil
}

func respondWithJSON(w http.ResponseWriter, r *http.Request, data any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	err := enc.Encode(data)
	if err != nil {
		slog.WarnContext(r.Context(), "Error writing JSON response", slog.Any("error", err))
	}
}
