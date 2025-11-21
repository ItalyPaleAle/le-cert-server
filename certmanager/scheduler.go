package certmanager

import (
	"context"
	"log"
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

	// Run once immediately
	s.checkAndRenew()

	for {
		select {
		case <-ticker.C:
			s.checkAndRenew()
		case <-s.ctx.Done():
			log.Println("Scheduler stopped")
			return
		}
	}
}

// checkAndRenew checks for expiring certificates and renews them
func (s *Scheduler) checkAndRenew() {
	log.Println("Checking for expiring certificates...")
	if err := s.manager.RenewExpiringCertificates(); err != nil {
		log.Printf("Error renewing certificates: %v\n", err)
	} else {
		log.Println("Certificate renewal check complete")
	}
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.cancel()
}
