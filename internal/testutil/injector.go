// Package testutil provides test utilities for VIGIL detection engine verification.
//
// AnomalySimulator reads real timing events from eBPF and injects artificial
// delay to simulate rootkit hooks. This tests the full detection pipeline
// (eBPF → ringbuf → detector → alert) without requiring a kernel module
// (which would need Secure Boot disabled).
//
// Academic basis: Trace of the Times (DTRAP 2025) proves rootkit hooks add
// measurable execution time. This simulator replicates that timing shift
// in userspace to verify VIGIL's statistical detection actually works.
package testutil

import (
	"context"
	"log"
	"time"

	"github.com/vigil/edr/internal/ebpf"
)

// AnomalySimulator injects synthetic timing anomalies into VIGIL's detection pipeline.
// It sits between the eBPF ringbuf reader and the detector, adding artificial delay
// to elapsed_ns values for targeted functions.
type AnomalySimulator struct {
	mgr      *ebpf.Manager
	delayNS  uint64 // Nanoseconds of artificial delay
	funcID   uint32 // Function ID to target (0 = all)
	duration time.Duration
	enabled  bool
	injected int
}

// NewAnomalySimulator creates a timing anomaly simulator.
// delayUS: microseconds of delay to add (simulates rootkit hook overhead)
// funcID: which function to target (0 = all functions)
// duration: how long to inject anomalies
func NewAnomalySimulator(mgr *ebpf.Manager, delayUS int, funcID uint32, duration time.Duration) *AnomalySimulator {
	if delayUS <= 0 {
		delayUS = 500
	}
	if duration <= 0 {
		duration = 30 * time.Second
	}
	return &AnomalySimulator{
		mgr:      mgr,
		delayNS:  uint64(delayUS) * 1000,
		funcID:   funcID,
		duration: duration,
		enabled:  true,
	}
}

// ReadEvent reads a timing event from eBPF and injects artificial delay.
// This replaces mgr.ReadEvent() in the detection pipeline when test mode is active.
func (as *AnomalySimulator) ReadEvent() (*ebpf.TimingEvent, error) {
	event, err := as.mgr.ReadEvent()
	if err != nil {
		return nil, err
	}

	if as.enabled && (as.funcID == 0 || event.FuncID == as.funcID) {
		event.ElapsedNS += as.delayNS
		as.injected++
	}

	return event, nil
}

// StartDeadline starts a goroutine that disables the simulator after duration.
func (as *AnomalySimulator) StartDeadline(ctx context.Context) {
	go func() {
		select {
		case <-time.After(as.duration):
			as.enabled = false
			log.Printf("[VIGIL-TEST] anomaly simulation ended (injected %d events, duration %v)",
				as.injected, as.duration)
		case <-ctx.Done():
			as.enabled = false
		}
	}()
}

// IsEnabled returns whether the simulator is still injecting anomalies.
func (as *AnomalySimulator) IsEnabled() bool {
	return as.enabled
}

// Injected returns the number of events that had delay injected.
func (as *AnomalySimulator) Injected() int {
	return as.injected
}