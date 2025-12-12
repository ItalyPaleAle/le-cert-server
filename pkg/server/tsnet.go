package server

import (
	"fmt"
	"net"
	"path/filepath"

	"tailscale.com/tsnet"

	"github.com/italypaleale/le-cert-server/pkg/config"
)

const defaultTsnetHostname = "le-cert-server"

type tsnetCleanupFn func() error

// createTSNetListener starts a tsnet server and returns a listener + TLS config.
// In tsnet mode we always serve HTTPS using Tailscale-provided certificates.
func (s *Server) createTSNetListener() (ln net.Listener, cleanup tsnetCleanupFn, err error) {
	cfg := config.Get()

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
		Store:     s.storage.TSNetStorage(),
	}

	ln, err = tsrv.ListenTLS("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		_ = tsrv.Close()
		return nil, nil, fmt.Errorf("failed to create tsnet listener: %w", err)
	}

	cleanup = func() error {
		return tsrv.Close()
	}
	return ln, cleanup, nil
}
