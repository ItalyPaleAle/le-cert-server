package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/italypaleale/le-cert-server/auth"
	"github.com/italypaleale/le-cert-server/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/buildinfo"
	"github.com/italypaleale/le-cert-server/pkg/config"
	appmetrics "github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/server"
	"github.com/italypaleale/le-cert-server/pkg/storage"
	"github.com/italypaleale/le-cert-server/pkg/utils"
	"github.com/italypaleale/le-cert-server/pkg/utils/logging"
	"github.com/italypaleale/le-cert-server/pkg/utils/servicerunner"
	"github.com/italypaleale/le-cert-server/pkg/utils/signals"
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

	// List of services to run
	services := make([]servicerunner.Service, 0, 3)

	// Shutdown functions
	shutdownFns := make([]servicerunner.Service, 0, 2)

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

	log.Info("Starting le-cert-server", slog.String("build", buildinfo.BuildDescription))

	// Get a context that is canceled when the application receives a termination signal
	// We store the logger in the context too
	ctx := signals.SignalContext(context.Background())

	// Init appMetrics
	appMetrics, metricsShutdownFn, err := appmetrics.NewAppMetrics(ctx)
	if err != nil {
		utils.FatalError(log, "Failed to init metrics", err)
		return
	}
	if metricsShutdownFn != nil {
		shutdownFns = append(shutdownFns, metricsShutdownFn)
	}

	// Initialize storage
	log.Info("Initializing database", slog.String("path", cfg.Database.Path))
	store, err := storage.NewStorage(cfg.Database.Path)
	if err != nil {
		utils.FatalError(log, "Failed to create storage", err)
		return
	}
	err = store.Init(ctx)
	if err != nil {
		utils.FatalError(log, "Failed to init storage", err)
		return
	}
	services = append(services, store.Run)

	// Create certificate manager
	certMgr := certmanager.NewCertManager(store)

	// Start certificate renewal scheduler
	const renewalSchedulerInterval = 12 * time.Hour
	log.Info("Starting certificate renewal scheduler", slog.String("interval", renewalSchedulerInterval.String()))
	scheduler := certmanager.NewScheduler(certMgr, renewalSchedulerInterval)
	services = append(services, scheduler.Run)

	// Create authenticator
	log.Info("Initializing OAuth2 authenticator", slog.String("issuer", cfg.Auth.IssuerURL))
	authenticator, err := auth.NewAuthenticator(cfg.Auth.IssuerURL, cfg.Auth.Audience, cfg.Auth.RequiredScopes)
	if err != nil {
		utils.FatalError(log, "Failed to init OAuth2 authenticator", err)
		return
	}

	// Create HTTP server
	log.Info("Initializing API server")
	apiServer, err := server.NewServer(server.NewServerOpts{
		AppMetrics:    appMetrics,
		Manager:       certMgr,
		Authenticator: authenticator,
	})
	if err != nil {
		utils.FatalError(log, "Failed to init API server", err)
		return
	}
	services = append(services, apiServer.Run)

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
