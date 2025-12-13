package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/italypaleale/le-cert-server/pkg/buildinfo"
	"github.com/italypaleale/le-cert-server/pkg/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/config"
	appmetrics "github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/server"
	"github.com/italypaleale/le-cert-server/pkg/server/auth"
	"github.com/italypaleale/le-cert-server/pkg/storage"
	"github.com/italypaleale/le-cert-server/pkg/tsnetserver"
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
	shutdownFns := make([]servicerunner.Service, 0, 3)

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
	certMgr := certmanager.NewCertManager(store, appMetrics)

	// Start certificate renewal scheduler
	const renewalSchedulerInterval = 12 * time.Hour
	log.Info("Starting certificate renewal scheduler", slog.String("interval", renewalSchedulerInterval.String()))
	scheduler := certmanager.NewScheduler(certMgr, renewalSchedulerInterval)
	services = append(services, scheduler.Run)

	// Start the tsnet server if needed
	var tsrv *tsnetserver.TSNetServer
	if cfg.Server.Listener == "tsnet" {
		tsrv, err = tsnetserver.NewTSNetServer(store)
		if err != nil {
			utils.FatalError(log, "Failed to create tsnet server", err)
			return
		}

		shutdownFns = append(shutdownFns, tsrv.Close)
	}

	// Create authenticator based on config type
	var authenticator auth.Authenticator
	switch {
	case cfg.Auth.JWT != nil:
		log.Info("Initializing JWT authenticator", slog.String("issuer", cfg.Auth.JWT.IssuerURL))
		authenticator, err = auth.NewJWTAuthenticator(ctx, cfg.Auth.JWT.IssuerURL, cfg.Auth.JWT.Audience, cfg.Auth.JWT.RequiredScopes)
		if err != nil {
			utils.FatalError(log, "Failed to init JWT authenticator", err)
			return
		}
	case cfg.Auth.PSK != nil:
		log.Info("Initializing PSK authenticator")
		authenticator, err = auth.NewPSKAuthenticator(cfg.Auth.PSK.Key)
		if err != nil {
			utils.FatalError(log, "Failed to init PSK authenticator", err)
			return
		}
	case cfg.Auth.TSNet != nil:
		log.Info("Initializing Tailscale identity authenticator")
		if tsrv == nil {
			// Indicates a development-time error; should never happen
			panic("config auth is tsnet but tsnet server not initialized")
		}

		// For TSNet auth, we need to create the tsnet server first to get its LocalClient
		localClient, err := tsrv.LocalClient()
		if err != nil {
			utils.FatalError(log, "Failed to get tsnet local client", err)
			return
		}
		authenticator, err = auth.NewTSNetAuthenticator(localClient, cfg.Auth.TSNet.AllowedTailnet)
		if err != nil {
			utils.FatalError(log, "Failed to init Tailscale authenticator", err)
			return
		}
	default:
		// Should never happen at this stage
		utils.FatalError(log, "Invalid auth configuration", errors.New("missing auth configuration"))
		return
	}

	// Create HTTP server
	log.Info("Initializing API server")
	apiServer, err := server.NewServer(server.NewServerOpts{
		AppMetrics:    appMetrics,
		Manager:       certMgr,
		Authenticator: authenticator,
		Storage:       store,
		TSNetServer:   tsrv,
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
