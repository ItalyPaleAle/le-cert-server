package certmanager

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Scheduler handles periodic certificate renewal checks
type Scheduler struct {
	manager  *CertManager
	interval time.Duration
}

// NewScheduler creates a new renewal scheduler
func NewScheduler(manager *CertManager, checkInterval time.Duration) *Scheduler {
	return &Scheduler{
		manager:  manager,
		interval: checkInterval,
	}
}

// Run the periodic renewal checks
func (s *Scheduler) Run(ctx context.Context) error {
	slog.Info("Scheduler started", "interval", s.interval)

	// Run once immediately
	err := s.manager.RenewExpiringCertificates()
	if err != nil {
		return fmt.Errorf("certificate renewal check failed: %w", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Info("Starting certificate renewal check")
			err = s.manager.RenewExpiringCertificates()
			if err != nil {
				// Log the error only, since we're in a background goroutine
				slog.Error("Certificate renewal check failed", "error", err)
			} else {
				slog.Info("Certificate renewal check completed successfully")
			}
		case <-ctx.Done():
			slog.Info("Scheduler stopped")
			return nil
		}
	}
}
