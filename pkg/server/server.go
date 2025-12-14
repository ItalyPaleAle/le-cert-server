package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	httpserver "github.com/italypaleale/go-kit/httpserver"
	slogkit "github.com/italypaleale/go-kit/slog"
	sloghttp "github.com/samber/slog-http"

	"github.com/italypaleale/le-cert-server/pkg/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/server/auth"
	"github.com/italypaleale/le-cert-server/pkg/storage"
	"github.com/italypaleale/le-cert-server/pkg/tsnetserver"
)

// Server is the server based on Gin
type Server struct {
	appSrv  *http.Server
	handler http.Handler
	running atomic.Bool
	wg      sync.WaitGroup

	appMetrics *metrics.AppMetrics
	manager    certmanager.CertManager
	auth       auth.Authenticator
	storage    *storage.Storage

	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn

	// TLS configuration for the app server
	tlsConfig *tls.Config

	// Listener for the app server
	// This can be used for testing without having to start an actual TCP listener
	appListener net.Listener

	// TSNet server instance (when using tsnet listener)
	tsnetServer *tsnetserver.TSNetServer
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	AppMetrics    *metrics.AppMetrics
	Manager       certmanager.CertManager
	Authenticator auth.Authenticator
	Storage       *storage.Storage
	TSNetServer   *tsnetserver.TSNetServer
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (*Server, error) {
	s := &Server{
		appMetrics:  opts.AppMetrics,
		manager:     opts.Manager,
		auth:        opts.Authenticator,
		storage:     opts.Storage,
		tsnetServer: opts.TSNetServer,
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
	cfg := config.Get()

	// Load the TLS configuration
	s.tlsConfig, s.tlsCertWatchFn, err = s.loadTLSConfig(context.Background())
	if err != nil {
		return fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	// Create the mux
	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("POST /api/certificate", httpserver.Use(http.HandlerFunc(s.handleGetCertificate), s.auth.Middleware))
	mux.Handle("POST /api/certificate/renew", httpserver.Use(http.HandlerFunc(s.handleRenewCertificate), s.auth.Middleware))

	middlewares := make([]httpserver.Middleware, 0, 4)
	middlewares = append(middlewares,
		// Recover from panics
		sloghttp.Recovery,
		// Limit request body to 1KB
		httpserver.MiddlewareMaxBodySize(1<<10),
	)

	filters := []sloghttp.Filter{
		sloghttp.IgnoreStatus(401, 404),
	}
	if cfg.Logs.OmitHealthChecks {
		filters = append(filters,
			func(w sloghttp.WrapResponseWriter, r *http.Request) bool {
				return r.URL.Path != "/healthz"
			},
		)
	}

	middlewares = append(middlewares,
		// Log requests
		sloghttp.NewWithFilters(slog.Default(), filters...),
	)

	// Add middlewares
	s.handler = httpserver.Use(mux, middlewares...)

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
	// Addr is used only for TCP listener creation; with tsnet we listen via tsnet.Server.
	addr := net.JoinHostPort(cfg.Server.Bind, strconv.Itoa(cfg.Server.Port))
	s.appSrv = &http.Server{
		Addr:              addr,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           s.handler,
	}

	// Create the listener if we don't have one already
	// If server.listener is tsnet, the listener is created using tsnet and it is already TLS-wrapped.
	var (
		serveWithTLS bool
		tsnetCleanup func() error
	)
	if s.appListener == nil {
		var err error
		switch cfg.Server.Listener {
		case "tcp":
			// Configure TLS for the HTTP server (optional)
			if s.tlsConfig == nil {
				// Not using TLS
				slog.WarnContext(ctx, "Starting app server without TLS - this is not recommended unless the app is exposed through a proxy that offers TLS termination")
				serveWithTLS = false
			} else {
				// Using TLS
				s.appSrv.TLSConfig = s.tlsConfig
				serveWithTLS = true
			}

			s.appListener, err = net.Listen("tcp", s.appSrv.Addr) //nolint:noctx
			if err != nil {
				return fmt.Errorf("failed to create TCP listener: %w", err)
			}

		case "tsnet":
			s.appListener, err = s.tsnetServer.Listen(cfg.Server.Port)
			if err != nil {
				return fmt.Errorf("failed to listen on tsnet: %w", err)
			}

			// Listener returned by createTSNetListener is already TLS-wrapped.
			serveWithTLS = false
		default:
			return fmt.Errorf("invalid server.listener value: %s", cfg.Server.Listener)
		}
	}

	// Start the HTTP(S) server in a background goroutine
	slog.InfoContext(ctx, "App server started",
		slog.String("bind", cfg.Server.Bind),
		slog.Int("port", cfg.Server.Port),
		slog.Bool("tls", s.tsnetServer != nil || s.tlsConfig != nil),
	)
	go func() { //nolint:contextcheck
		defer s.appListener.Close() //nolint:errcheck
		if tsnetCleanup != nil {
			defer tsnetCleanup() //nolint:errcheck
		}

		// Next call blocks until the server is shut down
		var srvErr error
		if serveWithTLS {
			srvErr = s.appSrv.ServeTLS(s.appListener, "", "")
		} else {
			srvErr = s.appSrv.Serve(s.appListener)
		}
		if !errors.Is(srvErr, http.ErrServerClosed) {
			slogkit.FatalError(slog.Default(), "Error starting app server", srvErr)
		}
	}()

	return nil
}
