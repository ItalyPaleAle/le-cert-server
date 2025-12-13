package server

import (
	"fmt"
	"net"
	"path/filepath"

	"tailscale.com/tsnet"

	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/pkg/storage"
)

const defaultTsnetHostname = "le-cert-server"

type tsnetCleanupFn func() error

// TSNetServer wraps a tsnet.Server for use in the application
type TSNetServer struct {
	Server *tsnet.Server
}

// NewTSNetServer creates a new TSNetServer instance
func NewTSNetServer(cfg *config.Config, store *storage.Storage) (*TSNetServer, error) {
	tsCfg := cfg.Server.TSNet

	stateDir := tsCfg.StateDir
	if stateDir == "" {
		loaded := cfg.GetLoadedConfigPath()
		if loaded != "" {
			stateDir = filepath.Join(filepath.Dir(loaded), "tsnet")
		}
	}

	hostname := tsCfg.Hostname
	if hostname == "" {
		hostname = defaultTsnetHostname
	}

	tsrv := &tsnet.Server{
		Hostname:  hostname,
		AuthKey:   tsCfg.AuthKey,
		Dir:       stateDir,
		Ephemeral: tsCfg.Ephemeral,
		Store:     store.TSNetStorage(),
	}

	return &TSNetServer{
		Server: tsrv,
	}, nil
}

// Close closes the tsnet server
func (t *TSNetServer) Close() error {
	if t.Server != nil {
		return t.Server.Close()
	}
	return nil
}

// createTSNetListener starts a tsnet server and returns a listener + TLS config.
// In tsnet mode we always serve HTTPS using Tailscale-provided certificates.
// If s.tsnetServer is set, it will reuse that server instead of creating a new one.
func (s *Server) createTSNetListener() (ln net.Listener, cleanup tsnetCleanupFn, err error) {
	cfg := config.Get()

	// If we already have a tsnet server (e.g., for TSNet auth), reuse it
	var tsrv *tsnet.Server
	if s.tsnetServer != nil {
		tsrv = s.tsnetServer.Server
	} else {
		// Create a new tsnet server
		tsCfg := cfg.Server.TSNet

		stateDir := tsCfg.StateDir
		if stateDir == "" {
			loaded := cfg.GetLoadedConfigPath()
			if loaded != "" {
				stateDir = filepath.Join(filepath.Dir(loaded), "tsnet")
			}
		}

		hostname := tsCfg.Hostname
		if hostname == "" {
			hostname = defaultTsnetHostname
		}

		tsrv = &tsnet.Server{
			Hostname:  hostname,
			AuthKey:   tsCfg.AuthKey,
			Dir:       stateDir,
			Ephemeral: tsCfg.Ephemeral,
			Store:     s.storage.TSNetStorage(),
		}
	}

	ln, err = tsrv.ListenTLS("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		_ = tsrv.Close()
		return nil, nil, fmt.Errorf("failed to create tsnet listener: %w", err)
	}

	cleanup = func() error {
		// Only close if we created the server ourselves
		if s.tsnetServer == nil {
			return tsrv.Close()
		}
		return nil
	}
	return ln, cleanup, nil
}
