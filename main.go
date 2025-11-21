package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/cert-server/auth"
	"github.com/yourusername/cert-server/certmanager"
	"github.com/yourusername/cert-server/config"
	"github.com/yourusername/cert-server/server"
	"github.com/yourusername/cert-server/storage"
)

func main() {
	// Set up structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Parse command-line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	logger.Info("loading configuration", "path", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize storage
	logger.Info("initializing database", "path", cfg.Database.Path)
	store, err := storage.NewStorage(cfg.Database.Path)
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Create certificate manager
	logger.Info("initializing certificate manager")
	certMgr := certmanager.NewCertManager(
		store,
		cfg.LetsEncrypt.Email,
		cfg.LetsEncrypt.Staging,
		cfg.LetsEncrypt.DNSProvider,
		cfg.LetsEncrypt.DNSCredentials,
		cfg.LetsEncrypt.RenewalDays,
		logger,
	)

	// Obtain initial certificate for the server itself if configured
	if cfg.LetsEncrypt.Domain != "" {
		logger.Info("obtaining certificate for server domain", "domain", cfg.LetsEncrypt.Domain)
		_, err := certMgr.ObtainCertificate(cfg.LetsEncrypt.Domain)
		if err != nil {
			logger.Warn("failed to obtain initial certificate", "error", err)
		}
	}

	// Start certificate renewal scheduler
	logger.Info("starting certificate renewal scheduler", "interval", "12h")
	scheduler := certmanager.NewScheduler(certMgr, 12*time.Hour)
	go scheduler.Start()
	defer scheduler.Stop()

	// Create authenticator
	logger.Info("initializing OAuth2 authenticator", "issuer", cfg.OAuth2.IssuerURL)
	authenticator, err := auth.NewAuthenticator(
		cfg.OAuth2.IssuerURL,
		cfg.OAuth2.Audience,
		cfg.OAuth2.Audiences,
		cfg.OAuth2.RequiredScopes,
		logger,
	)
	if err != nil {
		logger.Error("failed to initialize authenticator", "error", err)
		os.Exit(1)
	}

	// Create HTTP server
	logger.Info("initializing HTTP server")
	apiServer := server.NewServer(certMgr, authenticator, logger)

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
			logger.Info("starting HTTPS server", "address", cfg.Server.Address)
			if err := httpServer.ListenAndServeTLS(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTPS server failed", "error", err)
				os.Exit(1)
			}
		} else {
			logger.Warn("starting HTTP server without TLS - not recommended for production", "address", cfg.Server.Address)
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP server failed", "error", err)
				os.Exit(1)
			}
		}
	}()

	logger.Info("certificate server started successfully")

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server")

	// Gracefully shut down the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
	}

	logger.Info("server stopped")
}
