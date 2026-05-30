package certmanager

import (
	"context"
	"log/slog"
	"time"
)

// Scheduler handles periodic certificate renewal checks
type Scheduler struct {
	manager  CertManager
	interval time.Duration
}

// NewScheduler creates a new renewal scheduler
func NewScheduler(manager CertManager, checkInterval time.Duration) *Scheduler {
	return &Scheduler{
		manager:  manager,
		interval: checkInterval,
	}
}

// Run the periodic renewal checks
func (s *Scheduler) Run(ctx context.Context) error {
	slog.InfoContext(ctx, "Scheduler started", "interval", s.interval)

	// Run once immediately
	err := s.manager.RenewExpiringCertificates(ctx)
	if err != nil {
		// Treat this as non-fatal error, as it could be a transient Let's Encrypt failure
		// We can still serve cached certificates
		slog.ErrorContext(ctx, "Initial certificate renewal check failed", "error", err)
	} else {
		slog.InfoContext(ctx, "Initial certificate renewal check completed successfully")
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.InfoContext(ctx, "Starting certificate renewal check")
			err = s.manager.RenewExpiringCertificates(ctx)
			if err != nil {
				// Log the error only, since we're in a background goroutine
				slog.ErrorContext(ctx, "Certificate renewal check failed", "error", err)
			} else {
				slog.InfoContext(ctx, "Certificate renewal check completed successfully")
			}
		case <-ctx.Done():
			slog.InfoContext(ctx, "Scheduler stopped")
			return nil
		}
	}
}
