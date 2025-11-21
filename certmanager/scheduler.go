package certmanager

import (
	"context"
	"time"
)

// Scheduler handles periodic certificate renewal checks
type Scheduler struct {
	manager  *CertManager
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewScheduler creates a new renewal scheduler
func NewScheduler(manager *CertManager, checkInterval time.Duration) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		manager:  manager,
		interval: checkInterval,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins the periodic renewal checks
func (s *Scheduler) Start() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.manager.logger.Info("scheduler started", "interval", s.interval)

	// Run once immediately
	s.checkAndRenew()

	for {
		select {
		case <-ticker.C:
			s.checkAndRenew()
		case <-s.ctx.Done():
			s.manager.logger.Info("scheduler stopped")
			return
		}
	}
}

// checkAndRenew checks for expiring certificates and renews them
func (s *Scheduler) checkAndRenew() {
	s.manager.logger.Info("starting certificate renewal check")
	if err := s.manager.RenewExpiringCertificates(); err != nil {
		s.manager.logger.Error("certificate renewal check failed", "error", err)
	} else {
		s.manager.logger.Info("certificate renewal check completed successfully")
	}
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.cancel()
}
