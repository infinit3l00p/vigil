// © 2026 Dan Vladoiu. All rights reserved.

// Package fleet implements multi-host aggregation for VIGIL (v0.8.0).
//
// One binary, two roles:
//   - Agent:     fleet.collector_url set → periodically POSTs status + new
//     alerts to a central collector (gzip'd JSON, shared fleet token).
//   - Collector: fleet.collector_enabled = true → accepts agent reports,
//     keeps per-agent state + bounded alert history, and serves the fleet
//     view in the dashboard.
//
// Auth: agents authenticate with the shared fleet token (Bearer), which the
// dashboard's auth middleware accepts on /api/fleet/* routes only. Agents
// never hold the dashboard token.
package fleet

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
)

// FleetConfig configures fleet mode. Embedded in config.Config.Fleet.
// Every field must stay comparable — config.Merge does a struct != zero
// check (same rule as alert.RoutingConfig, see commit f2f0601).
type FleetConfig struct {
	// ── Agent side ─────────────────────────────────────────────────
	CollectorURL string `toml:"collector_url"` // collector report endpoint
	IntervalSec  int    `toml:"interval_sec"`  // report cadence (default 30)

	// ── Shared ─────────────────────────────────────────────────────
	Token string `toml:"token"` // shared fleet token (agents + collector must match)

	// ── Collector side ──────────────────────────────────────────────
	CollectorEnabled bool `toml:"collector_enabled"` // accept agent reports
	MaxAgents        int  `toml:"max_agents"`        // default 100
	RetentionMin     int  `toml:"retention_min"`     // prune agents unseen (default 15 min)
	AlertsPerAgent   int  `toml:"alerts_per_agent"`  // bounded alert ring (default 500)
}

func (c FleetConfig) interval() time.Duration {
	if c.IntervalSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.IntervalSec) * time.Second
}

func (c FleetConfig) maxAgents() int {
	if c.MaxAgents <= 0 {
		return 100
	}
	return c.MaxAgents
}

func (c FleetConfig) retention() time.Duration {
	if c.RetentionMin <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(c.RetentionMin) * time.Minute
}

func (c FleetConfig) alertsPerAgent() int {
	if c.AlertsPerAgent <= 0 {
		return 500
	}
	return c.AlertsPerAgent
}

// AgentStatus is the agent-side health snapshot included in every report.
type AgentStatus struct {
	BaselineReady      bool           `json:"baseline_ready"`
	EBPFEnabled        bool           `json:"ebpf_enabled"`
	ActiveModules      int            `json:"active_modules"`
	FunctionsMonitored int            `json:"functions_monitored"`
	AlertCounts        map[string]int `json:"alert_counts,omitempty"`
	UptimeSec          int64          `json:"uptime_sec"`
}

// Report is the payload an agent POSTs to the collector.
type Report struct {
	AgentID  string        `json:"agent_id"`
	Hostname string        `json:"hostname"`
	Version  string        `json:"version"`
	SentAt   time.Time     `json:"sent_at"`
	Status   AgentStatus   `json:"status"`
	Alerts   []alert.Alert `json:"alerts"`
}

// AgentInfo is the collector-side per-agent state; also the JSON served by
// GET /api/fleet/agents.
type AgentInfo struct {
	AgentID        string      `json:"agent_id"`
	Hostname       string      `json:"hostname"`
	Version        string      `json:"version"`
	IP             string      `json:"ip"`
	LastSeen       time.Time   `json:"last_seen"`
	Reports        int64       `json:"reports"`
	TotalAlerts    int64       `json:"total_alerts"`
	CriticalAlerts int64       `json:"critical_alerts"`
	Online         bool        `json:"online"`
	Status         AgentStatus `json:"status"`
}

// LoadOrCreateAgentID returns a stable agent ID persisted in dataDir
// (format: <hostname>-<6 hex chars>). Created once, reused across restarts
// so fleet history stays attached to the same agent.
func LoadOrCreateAgentID(dataDir string) string {
	path := filepath.Join(dataDir, "agent_id")
	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "vigil"
	}
	hostname = strings.ToLower(strings.ReplaceAll(hostname, " ", "-"))

	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		// crypto/rand failure is essentially impossible; degrade to time-based
		id := fmt.Sprintf("%s-%06x", hostname, time.Now().UnixNano()&0xffffff)
		_ = os.WriteFile(path, []byte(id), 0640)
		return id
	}
	id := hostname + "-" + hex.EncodeToString(suffix)
	if err := os.MkdirAll(dataDir, 0700); err == nil {
		_ = os.WriteFile(path, []byte(id), 0640)
	}
	return id
}

// ── Agent role: Reporter ───────────────────────────────────────────────

// Reporter is the agent-side fleet reporter. Alerts are buffered as they
// fire (via the alert callback bus) and batch-delivered on every tick.
type Reporter struct {
	mu          sync.Mutex
	cfg         FleetConfig
	agentID     string
	hostname    string
	version     string
	statusFn    func() AgentStatus
	client      *http.Client
	pending     []alert.Alert
	maxPending  int
	maxBatch    int
	logger      *zap.Logger
	lastErrLog  time.Time
	lastSuccess time.Time
	sentOK      int64
	sendFail    int64
}

// NewReporter creates an agent-side reporter. statusFn is called on every
// report cycle to snapshot agent health; it must be fast and non-blocking.
func NewReporter(cfg FleetConfig, agentID, version string, statusFn func() AgentStatus, logger *zap.Logger) *Reporter {
	hostname, _ := os.Hostname()
	return &Reporter{
		cfg:        cfg,
		agentID:    agentID,
		hostname:   hostname,
		version:    version,
		statusFn:   statusFn,
		client:     &http.Client{Timeout: 10 * time.Second},
		pending:    make([]alert.Alert, 0, 64),
		maxPending: 2000,
		maxBatch:   200,
		logger:     logger,
	}
}

// HandleAlert buffers an alert for the next report. Registered via
// alertMgr.SetCallback — must never block the detection path.
func (r *Reporter) HandleAlert(a alert.Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = append(r.pending, a)
	if len(r.pending) > r.maxPending {
		// Drop the oldest 10% — same eviction policy as the alert manager
		evict := r.maxPending / 10
		r.pending = r.pending[evict:]
	}
}

// Start runs the report loop until ctx is cancelled.
func (r *Reporter) Start(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.interval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sendOnce()
		}
	}
}

// sendOnce POSTs one gzip'd report. Alerts in a failed report stay buffered
// for the next cycle; a successful report removes exactly its own batch.
func (r *Reporter) sendOnce() bool {
	r.mu.Lock()
	batch := make([]alert.Alert, 0, r.maxBatch)
	if len(r.pending) <= r.maxBatch {
		batch = append(batch, r.pending...)
	} else {
		batch = append(batch, r.pending[:r.maxBatch]...)
	}
	status := r.statusFn()
	rep := Report{
		AgentID:  r.agentID,
		Hostname: r.hostname,
		Version:  r.version,
		SentAt:   time.Now(),
		Status:   status,
		Alerts:   batch,
	}
	r.mu.Unlock()

	body, err := json.Marshal(rep)
	if err != nil {
		r.logErrThrottled(fmt.Sprintf("marshal report: %v", err))
		return false
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(body)
	_ = gw.Close()

	req, err := http.NewRequest(http.MethodPost, r.cfg.CollectorURL, bytes.NewReader(gzBuf.Bytes()))
	if err != nil {
		r.logErrThrottled(fmt.Sprintf("build request: %v", err))
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		r.recordFailure()
		r.logErrThrottled(fmt.Sprintf("collector unreachable: %v", err))
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		r.recordFailure()
		r.logErrThrottled(fmt.Sprintf("collector rejected report: HTTP %d", resp.StatusCode))
		return false
	}

	// Success — drop exactly the delivered batch from the pending buffer.
	r.mu.Lock()
	if len(batch) <= len(r.pending) {
		r.pending = r.pending[len(batch):]
	}
	r.sentOK++
	r.lastSuccess = time.Now()
	r.mu.Unlock()
	return true
}

func (r *Reporter) recordFailure() {
	r.mu.Lock()
	r.sendFail++
	r.mu.Unlock()
}

// Stats returns reporter counters: pending alerts, successful/failed sends,
// and the time of the last successful report.
func (r *Reporter) Stats() (pending int, sentOK, sendFail int64, lastSuccess time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending), r.sentOK, r.sendFail, r.lastSuccess
}

func (r *Reporter) logErrThrottled(msg string) {
	r.mu.Lock()
	if time.Since(r.lastErrLog) < time.Minute {
		r.mu.Unlock()
		return
	}
	r.lastErrLog = time.Now()
	r.mu.Unlock()
	if r.logger != nil {
		r.logger.Warn("fleet reporter: " + msg)
	}
}

// ── Collector role: Collector ──────────────────────────────────────────

// onlineWindow is how long an agent stays "online" between reports
// (3× the default 30s interval).
const onlineWindow = 90 * time.Second

// Collector accepts and aggregates agent reports.
type Collector struct {
	mu     sync.RWMutex
	cfg    FleetConfig
	logger *zap.Logger
	agents map[string]*agentEntry
}

type agentEntry struct {
	info   AgentInfo
	alerts []alert.Alert // bounded ring, oldest first
}

// NewCollector creates a fleet collector.
func NewCollector(cfg FleetConfig, logger *zap.Logger) *Collector {
	return &Collector{
		cfg:    cfg,
		logger: logger,
		agents: make(map[string]*agentEntry),
	}
}

// AcceptReport stores an agent report. Stale agents are pruned first; new
// agents are rejected once MaxAgents is reached. Existing agents always
// update.
func (c *Collector) AcceptReport(rep Report, remoteIP string) error {
	if rep.AgentID == "" {
		return fmt.Errorf("empty agent_id")
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(now)

	if entry, ok := c.agents[rep.AgentID]; ok {
		c.applyLocked(entry, rep, remoteIP, now)
		return nil
	}
	if len(c.agents) >= c.cfg.maxAgents() {
		return fmt.Errorf("fleet full: max %d agents reached", c.cfg.maxAgents())
	}
	entry := &agentEntry{}
	c.agents[rep.AgentID] = entry
	c.applyLocked(entry, rep, remoteIP, now)
	if c.logger != nil {
		c.logger.Info("fleet: new agent registered",
			zap.String("agent_id", rep.AgentID),
			zap.String("hostname", rep.Hostname),
			zap.String("ip", remoteIP))
	}
	return nil
}

func (c *Collector) applyLocked(entry *agentEntry, rep Report, remoteIP string, now time.Time) {
	entry.info.AgentID = rep.AgentID
	entry.info.Hostname = rep.Hostname
	entry.info.Version = rep.Version
	entry.info.IP = remoteIP
	entry.info.LastSeen = now
	entry.info.Reports++
	entry.info.Status = rep.Status
	entry.info.Online = true

	maxAlerts := c.cfg.alertsPerAgent()
	for _, a := range rep.Alerts {
		entry.alerts = append(entry.alerts, a)
		if len(entry.alerts) > maxAlerts {
			entry.alerts = entry.alerts[len(entry.alerts)-maxAlerts:]
		}
		entry.info.TotalAlerts++
		if a.Level == alert.CRITICAL {
			entry.info.CriticalAlerts++
		}
	}
}

func (c *Collector) pruneLocked(now time.Time) {
	retention := c.cfg.retention()
	for id, e := range c.agents {
		if now.Sub(e.info.LastSeen) > retention {
			delete(c.agents, id)
		}
	}
}

// ListAgents returns all agents, sorted by most recently seen. Stale agents
// are pruned and freshness ("online") recomputed at list time.
func (c *Collector) ListAgents() []AgentInfo {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)

	out := make([]AgentInfo, 0, len(c.agents))
	for _, e := range c.agents {
		info := e.info
		info.Online = now.Sub(info.LastSeen) < onlineWindow
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// AgentAlerts returns the most recent alerts for one agent (oldest first),
// capped at max. Returns nil for unknown agents.
func (c *Collector) AgentAlerts(agentID string, max int) []alert.Alert {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.agents[agentID]
	if !ok {
		return nil
	}
	alerts := entry.alerts
	if max > 0 && len(alerts) > max {
		alerts = alerts[len(alerts)-max:]
	}
	out := make([]alert.Alert, len(alerts))
	copy(out, alerts)
	return out
}

// AgentCount returns the number of tracked agents.
func (c *Collector) AgentCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.agents)
}
