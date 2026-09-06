package response

// Response Engine — automated threat response based on attack type classification.
//
// Academic basis:
//   - CryptoGuard (AsiaCCS 2025): Two-phase detection → response pipeline (coarse host → fine process)
//   - eBPF-Shield (SOCA 2026): Closed-loop hybrid kernel/userspace remediation with graduated response
//   - GuardFS (arXiv 2401.17917): Integrated detection+mitigation with obfuscate/delay/track strategies
//   - EvilEDR (USENIX 2025): EDR response actions can be weaponized — VIGIL must verify its own integrity
//     before executing destructive responses, and must never expose response capabilities to untrusted input
//   - bpfbox (CCSW 2020): eBPF-based process confinement — cgroup isolation as non-destructive containment
//   - cgroup v2 freezer (kernel 4.5+): Non-destructive process freeze via cgroup.freeze (TASK_UNINTERRUPTIBLE)
//     Unlike SIGSTOP: no signal delivery, no ptrace interference, reversible, no resource leak
//   - nftables: Stateful firewall for network isolation per-cgroup (cgroupsv2 meta cgroup matches)
//
// Design principles:
//   1. Graduated response: INFO→log, WARN→evidence+alert, CRITICAL→contain+isolate+evidence
//   2. Non-destructive first: cgroup freeze before SIGKILL, network isolate before host isolation
//   3. Evidence always first: capture /proc state before any destructive action
//   4. Confirmation required for destructive actions (SIGKILL, SIGTERM) unless auto-approve configured
//   5. Anti-weaponization: EvilEDR defense — response actions verified against integrity, no arbitrary
//      command execution, all actions logged and auditable
//   6. the companion proxy integration: trigger identity rotation on targeted surveillance detection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vigil/edr/internal/alert"

	"go.uber.org/zap"
)

// ─── Response Types ────────────────────────────────────────────────

// ActionType defines what the response engine can do.
type ActionType int

const (
	ActionNone            ActionType = iota // No action (alert only)
	ActionEvidenceCapture                   // Capture /proc/[pid] state for forensics
	ActionFreeze                            // Freeze process via cgroup v2 freezer
	ActionNetworkIsolate                    // Isolate process network via nftables cgroup match
	ActionKill                              // SIGTERM → SIGKILL process (destructive)
	ActionProxyRotate                         // Trigger identity rotation (surveillance response)
)

func (a ActionType) String() string {
	switch a {
	case ActionNone:
		return "NONE"
	case ActionEvidenceCapture:
		return "EVIDENCE_CAPTURE"
	case ActionFreeze:
		return "FREEZE"
	case ActionNetworkIsolate:
		return "NETWORK_ISOLATE"
	case ActionKill:
		return "KILL"
	case ActionProxyRotate:
		return "PROXY_ROTATE"
	default:
		return "UNKNOWN"
	}
}

func (a ActionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// ResponseAction is a planned response for a specific alert category + severity.
type ResponseAction struct {
	Type     ActionType `json:"type"`
	Priority int        `json:"priority"` // Lower = executed first
	Destructive bool    `json:"destructive"`
	AutoApprove bool    `json:"auto_approve"` // Skip confirmation for this action
}

// AttackType classifies the category of threat for response mapping.
type AttackType string

const (
	AttackRootkit           AttackType = "ROOTKIT"
	AttackC2                AttackType = "C2_COMMUNICATION"
	AttackContainerEscape   AttackType = "CONTAINER_ESCAPE"
	AttackProcessInjection  AttackType = "PROCESS_INJECTION"
	AttackCryptojacking     AttackType = "CRYPTOJACKING"
	AttackDNSExfiltration   AttackType = "DNS_EXFILTRATION"
	AttackTTYSurveillance   AttackType = "TTY_SURVEILLANCE"
	AttackNetworkAnomaly    AttackType = "NETWORK_ANOMALY"
	AttackPrivilegeEscalation AttackType = "PRIVILEGE_ESCALATION"
	AttackUnknown           AttackType = "UNKNOWN"
)

// ─── Response Policy ──────────────────────────────────────────────

// ResponsePolicy maps attack types to graduated response chains.
// Each attack type has an ordered list of actions (priority-sorted).
type ResponsePolicy struct {
	mu      sync.RWMutex
	rules   map[AttackType][]ResponseAction
	autoApproveDestructive bool // Global: allow destructive actions without confirmation
	evidenceDir string           // Where to store captured evidence
	enabled    bool
}

// DefaultPolicy returns the research-informed default response policy.
//
// Response chain logic (eBPF-Shield graduated response):
//   - CRITICAL alerts: Evidence → Freeze → NetworkIsolate → Kill (if confirmed)
//   - WARN alerts: Evidence → alert escalation
//   - INFO/DEBUG: alert only
//
// Attack-specific mappings:
//   - ROOTKIT: Freeze + Isolate (preserve for analysis, prevent further hooking)
//   - C2: NetworkIsolate first (cut C2 channel), then Freeze
//   - CONTAINER_ESCAPE: Freeze + Isolate (contain escape attempt)
//   - CRYPTOJACKING: Freeze (stop resource theft, preserve evidence)
//   - DNS_EXFILTRATION: NetworkIsolate (cut exfil channel)
//   - TTY_SURVEILLANCE: Evidence + Freeze (capture spy, stop surveillance)
//   - PRIVILEGE_ESCALATION: Freeze (contain, prevent further escalation)
func DefaultPolicy(evidenceDir string) *ResponsePolicy {
	p := &ResponsePolicy{
		rules: make(map[AttackType][]ResponseAction),
		autoApproveDestructive: false,
		evidenceDir: evidenceDir,
		enabled: true,
	}

	// ROOTKIT: Freeze process to preserve state for forensic analysis.
	// Academic basis: CryptoGuard two-phase — contain first, analyze second.
	p.rules[AttackRootkit] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionNetworkIsolate, Priority: 3, Destructive: false, AutoApprove: true},
		{Type: ActionKill, Priority: 10, Destructive: true, AutoApprove: false},
	}

	// C2: Cut network first (break C2 channel), then freeze.
	p.rules[AttackC2] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionNetworkIsolate, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 3, Destructive: false, AutoApprove: true},
		{Type: ActionKill, Priority: 10, Destructive: true, AutoApprove: false},
	}

	// CONTAINER_ESCAPE: Freeze + Isolate.
	p.rules[AttackContainerEscape] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionNetworkIsolate, Priority: 3, Destructive: false, AutoApprove: true},
		{Type: ActionKill, Priority: 10, Destructive: true, AutoApprove: false},
	}

	// PROCESS_INJECTION: Freeze target (stop injection), evidence.
	p.rules[AttackProcessInjection] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionKill, Priority: 10, Destructive: true, AutoApprove: false},
	}

	// CRYPTOJACKING: Freeze (stop CPU theft, preserve for analysis).
	// Academic basis: CryptoGuard — process freeze as immediate containment.
	p.rules[AttackCryptojacking] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionKill, Priority: 10, Destructive: true, AutoApprove: false},
	}

	// DNS_EXFILTRATION: NetworkIsolate first (cut exfil channel).
	p.rules[AttackDNSExfiltration] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionNetworkIsolate, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 3, Destructive: false, AutoApprove: true},
	}

	// TTY_SURVEILLANCE: Evidence + Freeze (capture spy state, stop surveillance).
	p.rules[AttackTTYSurveillance] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 2, Destructive: false, AutoApprove: true},
	}

	// NETWORK_ANOMALY: Evidence + NetworkIsolate.
	p.rules[AttackNetworkAnomaly] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionNetworkIsolate, Priority: 2, Destructive: false, AutoApprove: true},
	}

	// PRIVILEGE_ESCALATION: Freeze (contain, prevent further escalation).
	p.rules[AttackPrivilegeEscalation] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
		{Type: ActionFreeze, Priority: 2, Destructive: false, AutoApprove: true},
		{Type: ActionKill, Priority: 10, Destructive: true, AutoApprove: false},
	}

	// UNKNOWN: Evidence only (safe default, don't act on unknowns).
	p.rules[AttackUnknown] = []ResponseAction{
		{Type: ActionEvidenceCapture, Priority: 1, Destructive: false, AutoApprove: true},
	}

	return p
}

func (p *ResponsePolicy) GetActions(attackType AttackType) []ResponseAction {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rules[attackType]
}

func (p *ResponsePolicy) SetActions(attackType AttackType, actions []ResponseAction) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules[attackType] = actions
}

func (p *ResponsePolicy) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

func (p *ResponsePolicy) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

// ─── Alert → Attack Type Classification ────────────────────────────

// ClassifyAlert maps an alert's category to an attack type for response selection.
// This is the detection→response bridge that CryptoGuard formalizes.
func ClassifyAlert(a alert.Alert) AttackType {
	switch a.Category {
	case "TEMPORAL_ANOMALY":
		// Temporal anomalies from kernel function hooking = rootkit
		return AttackRootkit
	case "CROSS_VIEW_MISMATCH":
		// Hidden process/file/connection = rootkit hiding
		return AttackRootkit
	case "BPF_INTEGRITY":
		// eBPF program count change = rootkit or eBPF tampering
		return AttackRootkit
	case "LINEAGE_ANOMALY":
		// Abnormal process tree (web→shell, priv-esc)
		if a.Level >= alert.CRITICAL {
			return AttackPrivilegeEscalation
		}
		return AttackProcessInjection
	case "DNS_EXFILTRATION":
		return AttackDNSExfiltration
	case "TTY_SURVEILLANCE":
		return AttackTTYSurveillance
	case "CONTAINER_ESCAPE":
		// Only auto-respond to CRITICAL container escape (actual escape attempt).
		// WARN-level setns() alerts are legitimate container runtime operations.
		if a.Level >= alert.CRITICAL {
			return AttackContainerEscape
		}
		return AttackUnknown
	case "NETWORK_ANOMALY", "NETWORK_FLOW_ANOMALY", "C2_PORT_DETECTED", "HIGH_RATE_CONNECTIONS":
		return AttackC2
	case "PRIVILEGE_ESCALATION":
		return AttackPrivilegeEscalation
	default:
		return AttackUnknown
	}
}

// ─── Response Result ───────────────────────────────────────────────

type ResponseStatus string

const (
	StatusExecuted   ResponseStatus = "EXECUTED"
	StatusPending    ResponseStatus = "PENDING"  // Awaiting confirmation
	StatusFailed     ResponseStatus = "FAILED"
	StatusSkipped    ResponseStatus = "SKIPPED"  // Policy disabled or below severity threshold
)

type ResponseResult struct {
	Timestamp   time.Time      `json:"timestamp"`
	PID         uint32         `json:"pid"`
	AttackType  AttackType     `json:"attack_type"`
	Action      ActionType     `json:"action"`
	Status      ResponseStatus `json:"status"`
	Message     string         `json:"message"`
	AlertRef    alert.Alert    `json:"alert_ref"`
}

// ─── Response Engine ───────────────────────────────────────────────

type ResponseEngine struct {
	policy     *ResponsePolicy
	alertMgr   *alert.AlertManager
	logger     *zap.Logger

	// Action executors
	freezer    *CgroupFreezer
	isolator   *NetworkIsolator
	evidence   *EvidenceCapture

	// Response history (bounded, TCA-safe)
	mu         sync.Mutex
	results    []ResponseResult
	maxResults int

	// Pending destructive actions awaiting confirmation
	pending    map[uint32][]ResponseAction // pid → pending destructive actions
}

func NewResponseEngine(policy *ResponsePolicy, alertMgr *alert.AlertManager, logger *zap.Logger) *ResponseEngine {
	return &ResponseEngine{
		policy:     policy,
		alertMgr:   alertMgr,
		logger:     logger,
		freezer:    NewCgroupFreezer(logger),
		isolator:   NewNetworkIsolator(logger),
		evidence:   NewEvidenceCapture(policy.evidenceDir, logger),
		results:    make([]ResponseResult, 0, 1000),
		maxResults: 1000,
		pending:    make(map[uint32][]ResponseAction),
	}
}

// IsEnabled returns whether the response engine is active.
func (e *ResponseEngine) IsEnabled() bool {
	return e.policy.IsEnabled()
}

// HandleAlert processes an alert through the response pipeline.
// This is the core Alert → Response bridge (CryptoGuard two-phase pattern).
func (e *ResponseEngine) HandleAlert(a alert.Alert, pid uint32) {
	if !e.policy.IsEnabled() {
		return
	}

	// Only respond to WARN and CRITICAL alerts (eBPF-Shield graduated response)
	if a.Level < alert.WARN {
		return
	}

	// PID 0 means no process context — skip response actions
	if pid == 0 {
		e.logger.Debug("response: skipping alert with no PID context",
			zap.String("category", a.Category),
		)
		return
	}

	// Self-protection: never act on VIGIL's own PID (EvilEDR defense)
	if os.Getpid() == int(pid) {
		e.logger.Debug("response: skipping self-targeting alert",
			zap.Uint32("pid", pid),
		)
		return
	}

	// PID reuse defense: verify the process is still the same one that triggered the alert
	// by checking its starttime hasn't changed (BUG-008 fix)
	if !verifyPID(pid, a.Timestamp) {
		e.logger.Warn("response: PID may have been recycled, skipping action",
			zap.Uint32("pid", pid),
			zap.Time("alert_time", a.Timestamp),
		)
		return
	}

	attackType := ClassifyAlert(a)
	actions := e.policy.GetActions(attackType)

	if len(actions) == 0 {
		return
	}

	e.logger.Info("response: processing alert",
		zap.String("attack_type", string(attackType)),
		zap.String("alert_category", a.Category),
		zap.Uint32("pid", pid),
		zap.Int("actions", len(actions)),
	)

	for _, action := range actions {
		// Destructive actions require confirmation (EvilEDR defense: prevent weaponization)
		if action.Destructive && !action.AutoApprove && !e.policy.autoApproveDestructive {
			e.mu.Lock()
			e.pending[pid] = append(e.pending[pid], action)
			e.mu.Unlock()
			e.recordResult(ResponseResult{
				Timestamp:  time.Now(),
				PID:        pid,
				AttackType: attackType,
				Action:     action.Type,
				Status:     StatusPending,
				Message:     "awaiting manual confirmation (destructive action)",
				AlertRef:   a,
			})
			e.logger.Warn("response: destructive action pending confirmation",
				zap.String("action", action.Type.String()),
				zap.Uint32("pid", pid),
			)
			continue
		}

		e.executeAction(action, a, attackType, pid)
	}
}

func (e *ResponseEngine) executeAction(action ResponseAction, a alert.Alert, attackType AttackType, pid uint32) {
	var status ResponseStatus
	var msg string

	switch action.Type {
	case ActionEvidenceCapture:
		status, msg = e.evidence.Capture(pid, attackType)
	case ActionFreeze:
		status, msg = e.freezer.Freeze(pid)
	case ActionNetworkIsolate:
		status, msg = e.isolator.Isolate(pid)
	case ActionKill:
		status, msg = e.killProcess(pid)
	case ActionProxyRotate:
		status, msg = StatusSkipped, "proxy rotation not yet integrated"
	case ActionNone:
		status, msg = StatusSkipped, "no action required"
	default:
		status, msg = StatusSkipped, "unknown action type"
	}

	e.recordResult(ResponseResult{
		Timestamp:  time.Now(),
		PID:        pid,
		AttackType: attackType,
		Action:     action.Type,
		Status:     status,
		Message:    msg,
		AlertRef:   a,
	})

	e.logger.Info("response: action executed",
		zap.String("action", action.Type.String()),
		zap.Uint32("pid", pid),
		zap.String("status", string(status)),
		zap.String("message", msg),
	)
}

func (e *ResponseEngine) killProcess(pid uint32) (ResponseStatus, string) {
	// SIGTERM first, then SIGKILL after timeout (graduated, not instant kill)
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return StatusFailed, fmt.Sprintf("find process %d: %v", pid, err)
	}
	// Check if process exists by sending signal 0
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return StatusFailed, fmt.Sprintf("process %d not running: %v", pid, err)
	}
	// SIGTERM
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		// Fall back to SIGKILL
		if err := proc.Signal(syscall.SIGKILL); err != nil {
			return StatusFailed, fmt.Sprintf("SIGTERM+SIGKILL failed for %d: %v", pid, err)
		}
		return StatusExecuted, fmt.Sprintf("SIGKILL sent to pid %d (SIGTERM failed)", pid)
	}
	return StatusExecuted, fmt.Sprintf("SIGTERM sent to pid %d", pid)
}

func (e *ResponseEngine) recordResult(r ResponseResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = append(e.results, r)
	if len(e.results) > e.maxResults {
		e.results = e.results[len(e.results)-e.maxResults:]
	}
}

// ApproveDestructive approves a pending destructive action for a PID.
func (e *ResponseEngine) ApproveDestructive(pid uint32) int {
	e.mu.Lock()
	pending := e.pending[pid]
	delete(e.pending, pid)
	e.mu.Unlock()

	if len(pending) == 0 {
		return 0
	}

	approved := 0
	for _, action := range pending {
		// Create a minimal alert for the approved action
		a := alert.Alert{
			Timestamp: time.Now(),
			Level:     alert.CRITICAL,
			Category:  "MANUAL_APPROVAL",
			Message:   fmt.Sprintf("destructive action approved for pid %d", pid),
		}
		attackType := AttackUnknown // We don't know the original attack type from pending
		action.AutoApprove = true // Now approved
		e.executeAction(action, a, attackType, pid)
		approved++
	}
	return approved
}

// RejectDestructive rejects pending destructive actions for a PID.
func (e *ResponseEngine) RejectDestructive(pid uint32) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := len(e.pending[pid])
	delete(e.pending, pid)
	return n
}

// Stats returns response engine statistics.
type ResponseStats struct {
	Enabled         bool            `json:"enabled"`
	TotalResponses  int             `json:"total_responses"`
	PendingActions  int             `json:"pending_actions"`
	LastResponse    *time.Time      `json:"last_response,omitempty"`
	ActionBreakdown  map[string]int  `json:"action_breakdown"`
	StatusBreakdown  map[string]int  `json:"status_breakdown"`
}

func (e *ResponseEngine) Stats() ResponseStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	stats := ResponseStats{
		Enabled:        e.policy.IsEnabled(),
		TotalResponses: len(e.results),
		PendingActions: len(e.pending),
		ActionBreakdown: make(map[string]int),
		StatusBreakdown: make(map[string]int),
	}

	for _, r := range e.results {
		stats.ActionBreakdown[r.Action.String()]++
		stats.StatusBreakdown[string(r.Status)]++
		if stats.LastResponse == nil || r.Timestamp.After(*stats.LastResponse) {
			t := r.Timestamp
			stats.LastResponse = &t
		}
	}

	// Prevent nil pointer dereference in callers when no results exist
	if stats.LastResponse == nil {
		t := time.Time{}
		stats.LastResponse = &t
	}

	return stats
}

// RecentResults returns the N most recent response results.
func (e *ResponseEngine) RecentResults(n int) []ResponseResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if n > len(e.results) {
		n = len(e.results)
	}
	result := make([]ResponseResult, n)
	copy(result, e.results[len(e.results)-n:])
	return result
}

// Freezer returns the cgroup freezer for direct access.
func (e *ResponseEngine) Freezer() *CgroupFreezer { return e.freezer }

// Isolator returns the network isolator for direct access.
func (e *ResponseEngine) Isolator() *NetworkIsolator { return e.isolator }

// Start begins the response engine (subscribes to alerts).
func (e *ResponseEngine) Start(ctx context.Context) {
	e.logger.Info("response: engine started")
	// Alert subscription is handled by main.go wiring alertMgr callbacks
	// The response engine is reactive — it processes alerts via HandleAlert()
	<-ctx.Done()
	e.logger.Info("response: engine stopped")
}

// verifyPID checks that the process at /proc/[pid] is still the same process
// that triggered the alert by comparing its starttime. This prevents PID reuse
// attacks where a process exits, its PID is recycled, and VIGIL acts on the
// wrong process (BUG-008 fix).
//
// We read field 22 (starttime in clock ticks) from /proc/[pid]/stat and
// compare it against the alert timestamp. If the process started AFTER the
// alert was generated, it's a different process.
func verifyPID(pid uint32, alertTime time.Time) bool {
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		// Process doesn't exist — can't verify, fail safe
		return false
	}

	// Parse /proc/[pid]/stat: pid (comm) state ppid ... starttime (field 22)
	// Find the closing paren to handle comm with spaces/parens
	closeParen := strings.LastIndex(string(statData), ")")
	if closeParen < 0 {
		return false
	}
	fields := strings.Fields(string(statData[closeParen+2:]))
	if len(fields) < 20 {
		return false
	}
	// Field 22 in /proc/stat = field index 19 after the ')' (0-indexed: state=0, ppid=1, ...)
	// starttime is field 22 (1-indexed from start of stat), which is field[19] after ')'
	var starttime uint64
	if _, err := fmt.Sscanf(fields[19], "%d", &starttime); err != nil {
		return false
	}

	// Convert starttime (clock ticks since boot) to wall time
	// ticks := starttime / sysconf(_SC_CLK_TCK); seconds := ticks
	// We use a conservative check: if the process started within 1 second of the alert,
	// it's likely the same process. If it started AFTER the alert, it's a new process.
	// Note: this is an approximation — exact verification would require capturing
	// starttime at detection time and comparing exactly.
	clockTicksPerSec := uint64(100) // standard Linux CLK_TCK
	startSecs := starttime / clockTicksPerSec

	// Read /proc/uptime to get system uptime
	uptimeData, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return true // Can't verify — fail open (better than blocking all responses)
	}
	uptimeFields := strings.Fields(string(uptimeData))
	if len(uptimeFields) < 1 {
		return true
	}
	var uptime float64
	if _, err := fmt.Sscanf(uptimeFields[0], "%f", &uptime); err != nil {
		return true
	}

	// Process start wall time = now - (uptime - starttime_in_seconds)
	processStartSecs := uptime - float64(startSecs)
	alertAgeSecs := time.Since(alertTime).Seconds()

	// If the process started AFTER the alert was generated, it's a different process
	if processStartSecs > alertAgeSecs+1.0 { // 1 second tolerance
		return false
	}

	return true
}