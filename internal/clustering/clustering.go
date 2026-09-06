// Package clustering implements behavioral process clustering for VIGIL.
//
// Based on: CryptoGuard (ASIACCS 2025) two-phase detection,
// eBPF-PATROL (arXiv 2511.18155) context-aware analysis.
//
// Correlates events from ALL VIGIL detection modules to identify
// processes that exhibit combinations of suspicious behaviors:
//   - CAP_SYS_ADMIN + opens /etc/shadow + renames itself = rootkit
//   - connect to unusual port + high DNS rate + spawned from web server = C2
//   - ptrace attach + injects code + privilege escalation = process injection
//   - unshare user ns + mount ns + setuid = container escape
package clustering

import (
	"context"
	"os"
	"strconv"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/models"
)

// ProcessBehaviorProfile aggregates suspicious indicators per process.
type ProcessBehaviorProfile struct {
	PID          uint32
	Comm         string
	FirstSeen    time.Time
	LastUpdated  time.Time

	// Indicator counts from each module
	TemporalAnomalies  int
	SyscallAlerts      int
	CrossViewMismatches int
	CredChanges        int
	PtraceEvents       int
	NamespaceEvents    int
	SUIDExecs          int
	DNSHighRate        bool
	DNSHighEntropy     bool
	TTYSuspiciousReads int
	ContainerEscape    bool
	FlowHighRate       bool
	FlowUnusualPorts   int
	BPFTampering       bool

	// Derived risk score
	RiskScore    int
	RiskCategory string // "benign", "suspicious", "malicious", "critical"
}

// ClusterRule defines a behavioral pattern that indicates a threat.
type ClusterRule struct {
	Name        string
	Description string
	Severity    string
	MinScore    int
	Required    []string // required indicators (ALL must be present)
	AnyOf       []string // any-of indicators (at least ONE must be present)
}

// DefaultClusterRules returns built-in behavioral clustering rules.
func DefaultClusterRules() []ClusterRule {
	return []ClusterRule{
		{
			Name: "rootkit-pattern", Description: "Rootkit behavioral pattern",
			Severity: "critical", MinScore: 80,
			Required: []string{"cred_change"},
			AnyOf:    []string{"cross_view_mismatch", "ptrace", "bpf_tampering", "tty_suspicious"},
		},
		{
			Name: "c2-pattern", Description: "C2 communication pattern",
			Severity: "critical", MinScore: 70,
			Required: []string{"flow_unusual_port"},
			AnyOf:    []string{"dns_high_rate", "flow_high_rate", "namespace_event"},
		},
		{
			Name: "container-escape", Description: "Container escape pattern",
			Severity: "critical", MinScore: 75,
			Required: []string{"namespace_event"},
			AnyOf:    []string{"cred_change", "suid_exec", "container_escape"},
		},
		{
			Name: "process-injection", Description: "Process injection pattern",
			Severity: "critical", MinScore: 70,
			Required: []string{"ptrace"},
			AnyOf:    []string{"cred_change", "cross_view_mismatch", "syscall_alert"},
		},
		{
			Name: "data-exfil", Description: "Data exfiltration pattern",
			Severity: "warn", MinScore: 50,
			Required: []string{"flow_high_rate"},
			AnyOf:    []string{"dns_high_rate", "tty_suspicious"},
		},
		{
			Name: "web-shell", Description: "Web shell pattern",
			Severity: "critical", MinScore: 60,
			Required: []string{"cred_change"},
			AnyOf:    []string{"flow_unusual_port", "dns_high_rate"},
		},
	}
}

// BehaviorClusterer manages behavioral clustering across all modules.
type BehaviorClusterer struct {
	mu      sync.Mutex
	alert   *alert.AlertManager
	logger  *zap.Logger
	profiles map[uint32]*ProcessBehaviorProfile
	rules   []ClusterRule
	stats   ClusterStats
	statsMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc

	// BUG-036: Track which (profile, rule) pairs have already fired an alert.
	// Only fire once per pair. Reset when the profile's risk score changes
	// significantly (i.e., a new indicator was added).
	firedAlerts map[string]int // key: "pid:ruleName" → riskScore at fire time
}

type ClusterStats struct {
	ProfilesTracked  int
	AlertsFired      int
	CriticalProcs    int
	SuspiciousProcs  int
	RuleMatches      int
}

func NewBehaviorClusterer(alertMgr *alert.AlertManager, logger *zap.Logger) *BehaviorClusterer {
	return &BehaviorClusterer{
		profiles:    make(map[uint32]*ProcessBehaviorProfile),
		rules:       DefaultClusterRules(),
		alert:       alertMgr,
		logger:      logger,
		firedAlerts: make(map[string]int),
	}
}

// Run starts the periodic clustering analysis.
func (bc *BehaviorClusterer) Run(ctx context.Context) {
	bc.ctx, bc.cancel = context.WithCancel(ctx)
	go bc.clusterLoop()
}

func (bc *BehaviorClusterer) clusterLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-bc.ctx.Done():
			return
		case <-ticker.C:
			bc.evaluate()
		}
	}
}

// UpdateProfile updates a process behavior profile from external modules.
func (bc *BehaviorClusterer) UpdateProfile(pid uint32, comm string, indicator string) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	profile, ok := bc.profiles[pid]
	if !ok {
		profile = &ProcessBehaviorProfile{
			PID:       pid,
			Comm:      comm,
			FirstSeen: time.Now(),
		}
		bc.profiles[pid] = profile
	}
	profile.LastUpdated = time.Now()

	// Track previous risk score to detect significant changes
	prevScore := profile.RiskScore

	switch indicator {
	case "temporal_anomaly":
		profile.TemporalAnomalies++
	case "syscall_alert":
		profile.SyscallAlerts++
	case "cross_view_mismatch":
		profile.CrossViewMismatches++
	case "cred_change":
		profile.CredChanges++
	case "ptrace":
		profile.PtraceEvents++
	case "namespace_event":
		profile.NamespaceEvents++
	case "suid_exec":
		profile.SUIDExecs++
	case "dns_high_rate":
		profile.DNSHighRate = true
	case "dns_high_entropy":
		profile.DNSHighEntropy = true
	case "tty_suspicious":
		profile.TTYSuspiciousReads++
	case "container_escape":
		profile.ContainerEscape = true
	case "flow_high_rate":
		profile.FlowHighRate = true
	case "flow_unusual_port":
		profile.FlowUnusualPorts++
	case "bpf_tampering":
		profile.BPFTampering = true
	}

	// Recalculate risk score
	profile.RiskScore = bc.calculateScore(profile)
	profile.RiskCategory = bc.categorize(profile.RiskScore)

	// BUG-036: If the risk score changed significantly (a new indicator was
	// added), reset fired alert tracking for this PID so rules can re-fire.
	scoreDiff := profile.RiskScore - prevScore
	if scoreDiff < 0 {
		scoreDiff = -scoreDiff
	}
	if scoreDiff >= 10 {
		for key := range bc.firedAlerts {
			if strings.HasPrefix(key, fmt.Sprintf("%d:", pid)) {
				delete(bc.firedAlerts, key)
			}
		}
	}
}

// calculateScore computes a risk score from the behavior profile.
func (bc *BehaviorClusterer) calculateScore(p *ProcessBehaviorProfile) int {
	score := 0

	// Temporal anomalies (strong signal)
	score += p.TemporalAnomalies * 20

	// Cross-view mismatches (very strong — means kernel hiding)
	score += p.CrossViewMismatches * 25

	// Credential changes (moderate — could be legitimate sudo)
	if p.CredChanges > 0 {
		score += 15
	}
	if p.CredChanges > 3 {
		score += 10
	}

	// ptrace (moderate — debuggers use it legitimately)
	score += p.PtraceEvents * 10

	// namespace events (moderate — container runtimes use these)
	if p.NamespaceEvents > 0 {
		score += 10
	}

	// SUID execs (moderate)
	if p.SUIDExecs > 0 {
		score += 10
	}

	// DNS anomalies (moderate)
	if p.DNSHighRate {
		score += 15
	}
	if p.DNSHighEntropy {
		score += 20
	}

	// TTY surveillance (strong for daemons)
	score += p.TTYSuspiciousReads * 20

	// Container escape (very strong)
	if p.ContainerEscape {
		score += 30
	}

	// Network flow anomalies (moderate)
	if p.FlowHighRate {
		score += 10
	}
	score += p.FlowUnusualPorts * 15

	// BPF tampering (very strong)
	if p.BPFTampering {
		score += 25
	}

	// Syscall alerts (moderate)
	score += p.SyscallAlerts * 5

	return score
}

// categorize maps a risk score to a category.
func (bc *BehaviorClusterer) categorize(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 50:
		return "malicious"
	case score >= 25:
		return "suspicious"
	default:
		return "benign"
	}
}

// evaluate applies all cluster rules to current profiles.
// BUG-035: Removes profiles for PIDs no longer in /proc.
// BUG-036: Only fires each (profile, rule) alert once; resets when risk score changes.
func (bc *BehaviorClusterer) evaluate() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// BUG-035: Clean up profiles for PIDs no longer in /proc
	activePIDs := bc.getActivePIDs()
	for pid := range bc.profiles {
		if !activePIDs[pid] {
			delete(bc.profiles, pid)
			// Also clean up fired alert tracking for this PID
			for key := range bc.firedAlerts {
				if strings.HasPrefix(key, fmt.Sprintf("%d:", pid)) {
					delete(bc.firedAlerts, key)
				}
			}
		}
	}

	criticalCount := 0
	suspiciousCount := 0

	for _, profile := range bc.profiles {
		if profile.RiskCategory == "critical" || profile.RiskCategory == "malicious" {
			criticalCount++
		} else if profile.RiskCategory == "suspicious" {
			suspiciousCount++
		}

		for _, rule := range bc.rules {
			if profile.RiskScore < rule.MinScore {
				continue
			}

			// Check required indicators
			allRequired := true
			for _, req := range rule.Required {
				if !bc.hasIndicator(profile, req) {
					allRequired = false
					break
				}
			}
			if !allRequired {
				continue
			}

			// Check any-of indicators
			anyMatch := len(rule.AnyOf) == 0
			for _, any := range rule.AnyOf {
				if bc.hasIndicator(profile, any) {
					anyMatch = true
					break
				}
			}
			if !anyMatch {
				continue
			}

			// BUG-036: Check if this (profile, rule) pair already fired.
			// Only fire once per pair; reset happens in UpdateProfile when
			// the risk score changes significantly.
			alertKey := fmt.Sprintf("%d:%s", profile.PID, rule.Name)
			if prevScore, fired := bc.firedAlerts[alertKey]; fired {
				// Already fired for this pair at prevScore. Skip unless
				// the risk score has changed significantly since then.
				if abs(profile.RiskScore-prevScore) < 10 {
					continue
				}
			}

			// Rule matched!
			bc.firedAlerts[alertKey] = profile.RiskScore

			bc.statsMu.Lock()
			bc.stats.RuleMatches++
			bc.stats.AlertsFired++
			bc.statsMu.Unlock()

			switch rule.Severity {
			case "critical":
				bc.alert.CriticalPID(0, string(models.CatBehavioralCluster),
					"BEHAVIORAL CLUSTER [%s]: %s — pid=%d comm=%s risk=%d(%s)",
					rule.Name, rule.Description, profile.PID, profile.Comm,
					profile.RiskScore, profile.RiskCategory)
			case "warn":
				bc.alert.WarnPID(0, string(models.CatBehavioralCluster),
					"BEHAVIORAL CLUSTER [%s]: %s — pid=%d comm=%s risk=%d(%s)",
					rule.Name, rule.Description, profile.PID, profile.Comm,
					profile.RiskScore, profile.RiskCategory)
			default:
				bc.alert.InfoPID(0, string(models.CatBehavioralCluster),
					"BEHAVIORAL CLUSTER [%s]: %s — pid=%d comm=%s risk=%d",
					rule.Name, rule.Description, profile.PID, profile.Comm,
					profile.RiskScore)
			}
		}
	}

	bc.statsMu.Lock()
	bc.stats.ProfilesTracked = len(bc.profiles)
	bc.stats.CriticalProcs = criticalCount
	bc.stats.SuspiciousProcs = suspiciousCount
	bc.statsMu.Unlock()
}

// getActivePIDs returns a set of PIDs currently in /proc.
func (bc *BehaviorClusterer) getActivePIDs() map[uint32]bool {
	active := make(map[uint32]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		bc.logger.Warn("clustering: failed to read /proc for stale cleanup", zap.Error(err))
		return active
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		active[uint32(pid)] = true
	}
	return active
}

// abs returns the absolute value of an integer.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// hasIndicator checks if a profile has a specific behavioral indicator.
func (bc *BehaviorClusterer) hasIndicator(p *ProcessBehaviorProfile, indicator string) bool {
	switch indicator {
	case "temporal_anomaly":
		return p.TemporalAnomalies > 0
	case "syscall_alert":
		return p.SyscallAlerts > 0
	case "cross_view_mismatch":
		return p.CrossViewMismatches > 0
	case "cred_change":
		return p.CredChanges > 0
	case "ptrace":
		return p.PtraceEvents > 0
	case "namespace_event":
		return p.NamespaceEvents > 0
	case "suid_exec":
		return p.SUIDExecs > 0
	case "dns_high_rate":
		return p.DNSHighRate
	case "dns_high_entropy":
		return p.DNSHighEntropy
	case "tty_suspicious":
		return p.TTYSuspiciousReads > 0
	case "container_escape":
		return p.ContainerEscape
	case "flow_high_rate":
		return p.FlowHighRate
	case "flow_unusual_port":
		return p.FlowUnusualPorts > 0
	case "bpf_tampering":
		return p.BPFTampering
	default:
		return false
	}
}

// Stats returns the current clustering statistics.
func (bc *BehaviorClusterer) Stats() ClusterStats {
	bc.statsMu.Lock()
	defer bc.statsMu.Unlock()
	return bc.stats
}

// GetProfile returns the behavior profile for a process.
func (bc *BehaviorClusterer) GetProfile(pid uint32) *ProcessBehaviorProfile {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	if p, ok := bc.profiles[pid]; ok {
		cp := *p
		return &cp
	}
	return nil
}

// TopRisks returns the N highest-risk process profiles.
func (bc *BehaviorClusterer) TopRisks(n int) []*ProcessBehaviorProfile {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Simple sort by risk score
	all := make([]*ProcessBehaviorProfile, 0, len(bc.profiles))
	for _, p := range bc.profiles {
		if p.RiskScore > 0 {
			cp := *p
			all = append(all, &cp)
		}
	}

	// Bubble sort (good enough for small N)
	for i := 0; i < len(all)-1; i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].RiskScore > all[i].RiskScore {
				all[i], all[j] = all[j], all[i]
			}
		}
	}

	if len(all) > n {
		all = all[:n]
	}
	return all
}

func (bc *BehaviorClusterer) Close() {
	if bc.cancel != nil {
		bc.cancel()
	}
}

// String returns a summary of the indicators present in a profile.
func (p *ProcessBehaviorProfile) String() string {
	var indicators []string
	if p.TemporalAnomalies > 0 {
		indicators = append(indicators, fmt.Sprintf("temporal=%d", p.TemporalAnomalies))
	}
	if p.CrossViewMismatches > 0 {
		indicators = append(indicators, fmt.Sprintf("hidden=%d", p.CrossViewMismatches))
	}
	if p.CredChanges > 0 {
		indicators = append(indicators, fmt.Sprintf("cred=%d", p.CredChanges))
	}
	if p.PtraceEvents > 0 {
		indicators = append(indicators, fmt.Sprintf("ptrace=%d", p.PtraceEvents))
	}
	if p.NamespaceEvents > 0 {
		indicators = append(indicators, fmt.Sprintf("ns=%d", p.NamespaceEvents))
	}
	if p.DNSHighRate {
		indicators = append(indicators, "dns_rate")
	}
	if p.DNSHighEntropy {
		indicators = append(indicators, "dns_entropy")
	}
	if p.TTYSuspiciousReads > 0 {
		indicators = append(indicators, "tty_suspicious")
	}
	if p.ContainerEscape {
		indicators = append(indicators, "container_esc")
	}
	if p.FlowHighRate {
		indicators = append(indicators, "flow_rate")
	}
	if p.FlowUnusualPorts > 0 {
		indicators = append(indicators, fmt.Sprintf("c2_port=%d", p.FlowUnusualPorts))
	}
	if p.BPFTampering {
		indicators = append(indicators, "bpf_tamper")
	}

	return fmt.Sprintf("pid=%d comm=%s risk=%d[%s] {%s}",
		p.PID, p.Comm, p.RiskScore, p.RiskCategory, strings.Join(indicators, ","))
}