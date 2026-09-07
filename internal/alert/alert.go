// Package alert implements VIGIL's alert management system.
//
// Alerts are the primary output of the detection engine. They are:
//   - Written to a log file for persistence
//   - Printed to console for real-time monitoring
//   - Future: sent to the companion proxy dashboard, webhooks, or other integrations
//
// Alert levels (from lowest to highest severity):
//   - debug: informational, no action needed
//   - info: notable but not threatening
//   - warn: potential anomaly, investigate
//   - critical: confirmed anomaly, immediate action required
//
// Academic basis: EvilEDR (USENIX Security 2025) demonstrates that EDRs
// can be repurposed as offensive tools. VIGIL must:
//   - Verify its own integrity (hash check on binary + config)
//   - Not expose more information than necessary in alerts
//   - Use bounded buffers to prevent alert flooding (TCA defense)
package alert

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level represents alert severity.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	CRITICAL
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON serializes Level as a string for dashboard compatibility.
func (l Level) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// ParseLevel parses a level string.
func ParseLevel(s string) Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return DEBUG
	case "INFO":
		return INFO
	case "WARN", "WARNING":
		return WARN
	case "CRITICAL", "CRIT":
		return CRITICAL
	default:
		return WARN
	}
}

// Alert represents a single detection alert.
type Alert struct {
	Timestamp time.Time `json:"time"`
	Level     Level       `json:"severity"`
	Category  string      `json:"category"`
	Message   string      `json:"message"`
	PID       uint32      `json:"pid,omitempty"` // Process that triggered the alert (0 if unknown)
}

// AlertManagerConfig holds configuration for an AlertManager.
type AlertManagerConfig struct {
	MinLevel   string
	LogPath    string
	MaxAlerts  int
	RateLimit  time.Duration // Per-(pid, category) rate limit window (default 60s)
}

// AlertManager manages alert output and filtering.
type AlertManager struct {
	mu        sync.Mutex
	minLevel  Level
	logFile   *os.File
	logger    *log.Logger
	alerts    []Alert
	maxAlerts int // Bounded alert buffer (TCA defense)
	callbacks []func(Alert) // v0.6.0: multiple listeners (response engine + router)

	// Rate limiting: per-(pid, category) last alert time
	rateLimit    time.Duration
	rateLastAlert map[uint32]map[string]time.Time // pid → category → last alert time

	// Global hard cap: prevents catastrophic alert flooding (BUG fix v7.2.17)
	globalAlertCount  int
	globalWindowStart time.Time
}

// New creates a new alert manager.
func New(level string, logPath string) *AlertManager {
	return NewWithConfig(AlertManagerConfig{
		MinLevel:  level,
		LogPath:   logPath,
		MaxAlerts: 10000,
		RateLimit: 60 * time.Second,
	})
}

// NewWithConfig creates a new alert manager from a config struct.
func NewWithConfig(cfg AlertManagerConfig) *AlertManager {
	if cfg.MaxAlerts <= 0 {
		cfg.MaxAlerts = 10000
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 60 * time.Second
	}
	am := &AlertManager{
		minLevel:      ParseLevel(cfg.MinLevel),
		maxAlerts:     cfg.MaxAlerts,
		alerts:        make([]Alert, 0, 1000),
		rateLimit:     cfg.RateLimit,
		rateLastAlert: make(map[uint32]map[string]time.Time),
	}

	// Set up log file
	if cfg.LogPath != "" {
		dir := filepath.Dir(cfg.LogPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[VIGIL] cannot create log dir %s: %v", dir, err)
		} else {
			f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				log.Printf("[VIGIL] cannot open log file %s: %v", cfg.LogPath, err)
			} else {
				am.logFile = f
				am.logger = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
			}
		}
	}

	return am
}

// Close closes the alert manager and flushes logs.
func (am *AlertManager) Close() {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.logFile != nil {
		am.logFile.Close()
	}
}

// Debug logs a debug-level alert.
func (am *AlertManager) Debug(category, format string, args ...interface{}) {
	am.emit(DEBUG, category, 0, format, args...)
}

// Info logs an info-level alert.
func (am *AlertManager) Info(category, format string, args ...interface{}) {
	am.emit(INFO, category, 0, format, args...)
}

// Warn logs a warning-level alert.
func (am *AlertManager) Warn(category, format string, args ...interface{}) {
	am.emit(WARN, category, 0, format, args...)
}

// Critical logs a critical-level alert.
func (am *AlertManager) Critical(category, format string, args ...interface{}) {
	am.emit(CRITICAL, category, 0, format, args...)
}

// CriticalPID logs a critical-level alert with PID context for the response engine.
func (am *AlertManager) CriticalPID(pid uint32, category, format string, args ...interface{}) {
	am.emit(CRITICAL, category, pid, format, args...)
}

// WarnPID logs a warning-level alert with PID context.
func (am *AlertManager) WarnPID(pid uint32, category, format string, args ...interface{}) {
	am.emit(WARN, category, pid, format, args...)
}

// InfoPID logs an info-level alert with PID context.
func (am *AlertManager) InfoPID(pid uint32, category, format string, args ...interface{}) {
	am.emit(INFO, category, pid, format, args...)
}

// emit writes an alert at the given level.
func (am *AlertManager) emit(level Level, category string, pid uint32, format string, args ...interface{}) {
	if level < am.minLevel {
		return
	}

	// Global hard cap: if we've emitted >200 alerts in the last 60 seconds,
	// drop everything. This prevents catastrophic log flooding from any module.
	// The per-(pid,category) rate limiter below handles normal throttling.
	am.mu.Lock()
	now := time.Now()
	if now.Sub(am.globalWindowStart) > 60*time.Second {
		am.globalWindowStart = now
		am.globalAlertCount = 0
	}
	am.globalAlertCount++
	if am.globalAlertCount > 200 {
		am.mu.Unlock()
		return // Hard cap: drop alert to prevent system freeze
	}
	am.mu.Unlock()

	// Rate limiting: per-(pid, category) suppression
	// When pid=0 (called via Warn/Critical without PID), apply per-category
	// global throttle to prevent alert floods from modules that don't pass PID.
	if am.rateLimit > 0 {
		am.mu.Lock()
		key := pid
		if key == 0 {
			key = ^uint32(0) // sentinel PID for global per-category throttle
		}
		if _, ok := am.rateLastAlert[key]; !ok {
			am.rateLastAlert[key] = make(map[string]time.Time)
		}
		if last, ok := am.rateLastAlert[key][category]; ok {
			if time.Since(last) < am.rateLimit {
				am.mu.Unlock()
				return // Suppress: too soon since last alert for this (pid, category)
			}
		}
		am.rateLastAlert[key][category] = time.Now()
		am.mu.Unlock()
	}

	msg := fmt.Sprintf(format, args...)
	alert := Alert{
		Timestamp: now,
		Level:     level,
		Category:  category,
		Message:   msg,
		PID:       pid,
	}

	// Console output
	log.Printf("[VIGIL] [%s] [%s] %s", level, category, msg)

	// File output
	if am.logger != nil {
		am.logger.Printf("[%s] [%s] %s", level, category, msg)
	}

	// In-memory buffer (bounded)
	am.mu.Lock()
	if len(am.alerts) >= am.maxAlerts {
		// Evict oldest 10% to prevent unbounded growth
		evictCount := am.maxAlerts / 10
		am.alerts = am.alerts[evictCount:]
	}
	am.alerts = append(am.alerts, alert)
	am.mu.Unlock()

	// Fire callbacks (response engine, router, etc.) — each in its own
	// goroutine so a slow listener can never stall detection.
	for _, cb := range am.callbacks {
		if cb != nil {
			go cb(alert)
		}
	}
}

// Flush clears stale rate limit entries older than the rate limit window.
// This should be called periodically to prevent unbounded growth of the rate
// limit map for processes that have exited.
func (am *AlertManager) Flush() {
	am.mu.Lock()
	defer am.mu.Unlock()
	if am.rateLimit <= 0 {
		return
	}
	cutoff := time.Now().Add(-am.rateLimit)
	for pid, categories := range am.rateLastAlert {
		for cat, last := range categories {
			if last.Before(cutoff) {
				delete(categories, cat)
			}
		}
		if len(categories) == 0 {
			delete(am.rateLastAlert, pid)
		}
	}
}

// GetAlerts returns recent alerts, optionally filtered by minimum level.
// SetCallback registers a function called on every emitted alert.
// Used by the response engine for Alert → Response pipeline.
// v0.6.0: appends — multiple listeners can coexist (response engine + router).
func (am *AlertManager) SetCallback(fn func(Alert)) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.callbacks = append(am.callbacks, fn)
}

func (am *AlertManager) GetAlerts(minLevel Level) []Alert {
	am.mu.Lock()
	defer am.mu.Unlock()

	result := make([]Alert, 0, len(am.alerts))
	for _, a := range am.alerts {
		if a.Level >= minLevel {
			result = append(result, a)
		}
	}
	return result
}

// AlertCount returns the total number of alerts by level.
func (am *AlertManager) AlertCount() map[Level]int {
	am.mu.Lock()
	defer am.mu.Unlock()

	counts := make(map[Level]int)
	for _, a := range am.alerts {
		counts[a.Level]++
	}
	return counts
}