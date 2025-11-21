package main

import (
	"context"
	"flag"
	"log"
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
	// Parse command-line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	log.Printf("Loading configuration from %s", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize storage
	log.Printf("Initializing database at %s", cfg.Database.Path)
	store, err := storage.NewStorage(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Create certificate manager
	log.Println("Initializing certificate manager")
	certMgr := certmanager.NewCertManager(
		store,
		cfg.LetsEncrypt.Email,
		cfg.LetsEncrypt.Staging,
		cfg.LetsEncrypt.DNSProvider,
		cfg.LetsEncrypt.DNSCredentials,
		cfg.LetsEncrypt.RenewalDays,
	)

	// Obtain initial certificate for the server itself if configured
	if cfg.LetsEncrypt.Domain != "" {
		log.Printf("Obtaining certificate for server domain: %s", cfg.LetsEncrypt.Domain)
		_, err := certMgr.ObtainCertificate(cfg.LetsEncrypt.Domain)
		if err != nil {
			log.Printf("Warning: Failed to obtain initial certificate: %v", err)
		}
	}

	// Start certificate renewal scheduler
	log.Printf("Starting certificate renewal scheduler (checking every 12 hours)")
	scheduler := certmanager.NewScheduler(certMgr, 12*time.Hour)
	go scheduler.Start()
	defer scheduler.Stop()

	// Create authenticator
	authenticator := auth.NewAuthenticator(cfg.OAuth2.BearerToken)

	// Create HTTP server
	log.Println("Initializing HTTP server")
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
		log.Printf("Starting HTTPS server on %s", cfg.Server.Address)
		if cfg.Server.TLSCertPath != "" && cfg.Server.TLSKeyPath != "" {
			if err := httpServer.ListenAndServeTLS(cfg.Server.TLSCertPath, cfg.Server.TLSKeyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start HTTPS server: %v", err)
			}
		} else {
			log.Println("Warning: Starting HTTP server (no TLS configured)")
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start HTTP server: %v", err)
			}
		}
	}()

	log.Println("Certificate server started successfully")

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Gracefully shut down the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
