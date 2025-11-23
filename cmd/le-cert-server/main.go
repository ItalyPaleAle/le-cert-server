package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/italypaleale/le-cert-server/auth"
	"github.com/italypaleale/le-cert-server/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/buildinfo"
	"github.com/italypaleale/le-cert-server/pkg/config"
	appmetrics "github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/utils"
	"github.com/italypaleale/le-cert-server/pkg/utils/logging"
	"github.com/italypaleale/le-cert-server/pkg/utils/servicerunner"
	"github.com/italypaleale/le-cert-server/pkg/utils/signals"
	"github.com/italypaleale/le-cert-server/server"
	"github.com/italypaleale/le-cert-server/storage"
)

func main() {
	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	err := config.LoadConfig()
	if err != nil {
		var ce *config.ConfigError
		if errors.As(err, &ce) {
			ce.LogFatal(initLogger)
		} else {
			utils.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}
	cfg := config.Get()

	// Shutdown functions
	shutdownFns := make([]servicerunner.Service, 0)

	// Get the logger and set it in the context
	log, loggerShutdownFn, err := logging.GetLogger(context.Background(), cfg)
	if err != nil {
		utils.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	if loggerShutdownFn != nil {
		shutdownFns = append(shutdownFns, loggerShutdownFn)
	}

	// Validate the configuration
	err = cfg.Validate(log)
	if err != nil {
		utils.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting le-cert-server", "build", buildinfo.BuildDescription)

	// Get a context that is canceled when the application receives a termination signal
	// We store the logger in the context too
	ctx := signals.SignalContext(context.Background())

	// Init metrics
	metrics, metricsShutdownFn, err := appmetrics.NewAppMetrics(ctx)
	if err != nil {
		utils.FatalError(log, "Failed to init metrics", err)
		return
	}
	if metricsShutdownFn != nil {
		shutdownFns = append(shutdownFns, metricsShutdownFn)
	}

	// Initialize storage
	log.Info("Initializing database", "path", cfg.Database.Path)
	store, err := storage.NewStorage(cfg.Database.Path)
	if err != nil {
		utils.FatalError(log, "Failed to init storage", err)
		return
	}
	defer store.Close()

	// Create certificate manager
	log.Info("Initializing certificate manager")
	certMgr := certmanager.NewCertManager(store)

	// Obtain initial certificate for the server itself if configured
	if cfg.LetsEncrypt.Domain != "" {
		log.Info("Obtaining certificate for server domain", "domain", cfg.LetsEncrypt.Domain)
		_, err := certMgr.ObtainCertificate(cfg.LetsEncrypt.Domain)
		if err != nil {
			log.Warn("failed to obtain initial certificate", "error", err)
		}
	}

	// Start certificate renewal scheduler
	log.Info("Starting certificate renewal scheduler", "interval", "12h")
	scheduler := certmanager.NewScheduler(certMgr, 12*time.Hour)
	go scheduler.Start()
	defer scheduler.Stop()

	// Create authenticator
	log.Info("Initializing OAuth2 authenticator", "issuer", cfg.Auth.IssuerURL)
	authenticator, err := auth.NewAuthenticator(cfg.Auth.IssuerURL, cfg.Auth.Audience, cfg.Auth.RequiredScopes)
	if err != nil {
		utils.FatalError(log, "Failed to init authenticator", err)
		return
	}

	// Create HTTP server
	log.Info("Initializing HTTP server")
	apiServer := server.NewServer(certMgr, authenticator)

	// Configure HTTPS server
	httpServer := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      apiServer.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTPS server in a goroutine
	go func() {
		if cfg.Server.TLSCertPath != "" && cfg.Server.TLSKeyPath != "" {
			log.Info("Starting HTTPS server", "address", cfg.Server.Address)
			err = httpServer.ListenAndServeTLS(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath)
			if err != nil && err != http.ErrServerClosed {
				log.Error("HTTPS server failed", "error", err)
				os.Exit(1)
			}
		} else {
			log.Warn("Starting HTTP server without TLS - not recommended for production", "address", cfg.Server.Address)
			err = httpServer.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Error("HTTP server failed", "error", err)
				os.Exit(1)
			}
		}
	}()

	log.Info("Certificate server started successfully")

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server")

	// Gracefully shut down the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("Server stopped")

	// Run all services
	// This call blocks until the context is canceled
	err = servicerunner.
		NewServiceRunner(services...).
		Run(ctx)
	if err != nil {
		utils.FatalError(log, "Failed to run service", err)
		return
	}

	// Invoke all shutdown functions
	// We give these a timeout of 5s
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = servicerunner.
		NewServiceRunner(shutdownFns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
