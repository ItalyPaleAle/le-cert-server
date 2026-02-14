package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	configkit "github.com/italypaleale/go-kit/config"
	"github.com/italypaleale/go-kit/observability"
	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/italypaleale/go-kit/signals"
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/italypaleale/go-kit/tsnetserver"

	"github.com/italypaleale/le-cert-server/pkg/buildinfo"
	"github.com/italypaleale/le-cert-server/pkg/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/config"
	appmetrics "github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/server"
	"github.com/italypaleale/le-cert-server/pkg/server/auth"
	"github.com/italypaleale/le-cert-server/pkg/storage"
)

func main() {
	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	cfg := config.Get()
	err := configkit.LoadConfig(cfg, configkit.LoadConfigOpts{
		EnvVar:  "LECERTSERVER_CONFIG",
		DirName: "le-cert-server",
	})
	if err != nil {
		var ce *configkit.ConfigError
		if errors.As(err, &ce) {
			ce.LogFatal(initLogger)
		} else {
			slogkit.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}

	// List of services to run
	services := make([]servicerunner.Service, 0, 3)
	shutdowns := &shutdownManager{
		fns: make([]servicerunner.Service, 0, 4),
	}

	// Get the logger and set it in the context
	log, loggerShutdownFn, err := observability.InitLogs(context.Background(), observability.InitLogsOpts{
		Config:     cfg,
		Level:      cfg.Logs.Level,
		JSON:       cfg.Logs.JSON,
		AppName:    buildinfo.AppName,
		AppVersion: buildinfo.AppVersion,
	})
	if err != nil {
		slogkit.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	shutdowns.Add(loggerShutdownFn)

	// Validate the configuration
	err = cfg.Validate(log)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting le-cert-server", slog.String("build", buildinfo.BuildDescription))

	// Get a context that is canceled when the application receives a termination signal
	// We store the logger in the context too
	ctx := signals.SignalContext(context.Background())

	// Init appMetrics
	appMetrics, metricsShutdownFn, err := appmetrics.NewAppMetrics(ctx)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init metrics", err)
		return
	}
	shutdowns.Add(metricsShutdownFn)

	traceProvider, tracerShutdownFn, err := observability.InitTraces(ctx, observability.InitTracesOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
	})
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init tracing", err)
		return
	}
	shutdowns.Add(tracerShutdownFn)

	// Initialize storage
	log.Info("Initializing database", slog.String("path", cfg.Database.Path))
	store, err := storage.NewStorage(cfg.Database.Path)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to create storage", err)
		return
	}
	err = store.Init(ctx)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init storage", err)
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
		tsrv, err = tsnetserver.NewTSNetServer(ctx, tsnetserver.NewTSNetServerOpts{
			Hostname:  cfg.Server.TSNet.Hostname,
			AuthKey:   cfg.Server.TSNet.AuthKey,
			StateDir:  cfg.GetTSNetStateDir(),
			Ephemeral: cfg.Server.TSNet.Ephemeral,
		})
		if err != nil {
			shutdowns.Run(log)
			slogkit.FatalError(log, "Failed to create tsnet server", err)
			return
		}

		shutdowns.Add(tsrv.Close)
	}

	// Create authenticator based on config type
	var authenticator auth.Authenticator
	switch cfg.Auth.Method {
	case "jwt":
		log.Info("Initializing JWT authenticator", slog.String("issuer", cfg.Auth.JWT.IssuerURL))
		authenticator, err = auth.NewJWTAuthenticator(
			ctx,
			cfg.Auth.JWT.IssuerURL,
			cfg.Auth.JWT.Audience,
			cfg.Auth.JWT.RequiredScopes,
			cfg.Auth.JWT.DomainsClaim,
		)
		if err != nil {
			shutdowns.Run(log)
			slogkit.FatalError(log, "Failed to init JWT authenticator", err)
			return
		}
	case "psk":
		log.Info("Initializing PSK authenticator")
		authenticator, err = auth.NewPSKAuthenticator(cfg.Auth.PSK.Key)
		if err != nil {
			shutdowns.Run(log)
			slogkit.FatalError(log, "Failed to init PSK authenticator", err)
			return
		}
	case "tsnet":
		log.Info("Initializing Tailscale identity authenticator")
		if tsrv == nil {
			// Indicates a development-time error; should never happen
			panic("config auth is tsnet but tsnet server not initialized")
		}

		// For TSNet auth, we need to create the tsnet server
		authenticator, err = auth.NewTSNetAuthenticator(tsrv)
		if err != nil {
			shutdowns.Run(log)
			slogkit.FatalError(log, "Failed to init Tailscale authenticator", err)
			return
		}
	default:
		// Should never happen at this stage
		slogkit.FatalError(log, "Invalid auth configuration", errors.New("missing auth configuration"))
		return
	}

	// Create HTTP server
	log.Info("Initializing API server")
	apiServer, err := server.NewServer(server.NewServerOpts{
		AppMetrics:    appMetrics,
		TraceProvider: traceProvider,
		Manager:       certMgr,
		Authenticator: authenticator,
		Storage:       store,
		TSNetServer:   tsrv,
	})
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init API server", err)
		return
	}
	services = append(services, apiServer.Run)

	// Run all services
	// This call blocks until the context is canceled
	err = servicerunner.
		NewServiceRunner(services...).
		Run(ctx)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to run service", err)
		return
	}

	shutdowns.Run(log)
}

type shutdownManager struct {
	fns []servicerunner.Service
}

func (s *shutdownManager) Add(fn servicerunner.Service) {
	if fn == nil {
		return
	}
	s.fns = append(s.fns, fn)
}

func (s *shutdownManager) Run(log *slog.Logger) {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err := servicerunner.
		NewServiceRunner(s.fns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
