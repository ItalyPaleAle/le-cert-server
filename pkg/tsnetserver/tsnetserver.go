package tsnetserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/pkg/storage"
)

// TSNetServer wraps a tsnet.Server for use in the application
type TSNetServer struct {
	server *tsnet.Server
}

// NewTSNetServer creates a new TSNetServer instance
func NewTSNetServer(store *storage.Storage) (*TSNetServer, error) {
	cfg := config.Get()

	stateDir := cfg.Server.TSNet.StateDir
	if stateDir == "" {
		loaded := cfg.GetLoadedConfigPath()
		if loaded != "" {
			stateDir = filepath.Join(filepath.Dir(loaded), "tsnet")
		}
	}

	tsLogger := slog.With("scope", "tsnet")
	tsrv := &tsnet.Server{
		Hostname:  cfg.Server.TSNet.Hostname,
		AuthKey:   cfg.Server.TSNet.AuthKey,
		Dir:       stateDir,
		Ephemeral: cfg.Server.TSNet.Ephemeral,
		Store:     store.TSNetStorage(),
		Logf: func(format string, args ...any) {
			tsLogger.Info(fmt.Sprintf(format, args...))
		},
	}

	return &TSNetServer{
		server: tsrv,
	}, nil
}

func (t *TSNetServer) LocalClient() (*local.Client, error) {
	lc, err := t.server.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get Tailscale local client: %w", err)
	}

	return lc, nil
}

func (t *TSNetServer) Listen(port int) (net.Listener, error) {
	ln, err := t.server.ListenTLS("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		_ = t.server.Close()
		return nil, fmt.Errorf("failed to create tsnet listener: %w", err)
	}

	return ln, nil
}

// Close closes the tsnet server
func (t *TSNetServer) Close(_ context.Context) error {
	err := t.server.Close()
	if err != nil {
		return fmt.Errorf("failed to close tsnet server: %w", err)
	}
	return nil
}
