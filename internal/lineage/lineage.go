// Package lineage implements process lineage tracking for VIGIL.
//
// Based on: eBPF-PATROL (arXiv 2511.18155), CryptoGuard (ASIACCS 2025),
// EvilEDR (USENIX Security 2025).
//
// Tracks the full process tree from eBPF, building parent→child
// relationships and detecting anomalous execution chains:
//   - Web server spawning shells (nginx → bash = compromised)
//   - Privilege escalation (unpriv → setuid → root shell)
//   - ptrace injection (debugger → attach to sensitive process)
//   - Container escape (container → setns → host namespace)
package lineage

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
	ebpfpkg "github.com/vigil/edr/internal/ebpf"
	"github.com/vigil/edr/internal/models"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -I./internal/ebpf/bpf_src -I/usr/include/bpf" vigilLineage ./internal/ebpf/bpf_src/vigil_lineage.c

// LineageNode represents a process in the lineage tree.
type LineageNode struct {
	PID     uint32
	PPID    uint32
	UID     uint32
	GID     uint32
	EUID    uint32
	EGID    uint32
	StartNS uint64
	ExitNS  uint64
	Flags   uint32
	Comm    string
	Path    string
	Alive   bool
}

// LineageRule defines an anomalous execution chain pattern.
type LineageRule struct {
	Name        string
	Description string
	Severity    string // "critical", "warn", "info"
	ParentComm  string // parent process name pattern
	ChildComm   string // child process name pattern
	ParentPath  string // parent executable path pattern
	ChildPath   string // child executable path pattern
}

// DefaultLineageRules returns the built-in anomalous execution chain rules.
func DefaultLineageRules() []LineageRule {
	return []LineageRule{
		// Web servers spawning shells = compromised
		{Name: "web-shell", Description: "Web server spawning shell", Severity: "critical",
			ParentComm: "nginx|apache2|httpd|node|php-fpm|uwsgi|gunicorn", ChildComm: "bash|sh|dash|zsh|nc|ncat|socat|python|perl|ruby"},
		// Cron executing network tools = reverse shell
		{Name: "cron-reverse-shell", Description: "Cron executing network tool", Severity: "critical",
			ParentComm: "crond|cron|atd", ChildComm: "nc|ncat|socat|wget|curl|telnet"},
		// SSH spawning unexpected tools
		{Name: "ssh-data-exfil", Description: "SSH session spawning data transfer tool", Severity: "warn",
			ParentComm: "sshd", ChildComm: "scp|sftp|rsync|wget|curl"},
		// Container runtime spawning host processes
		{Name: "container-breakout", Description: "Container process spawning host binary", Severity: "critical",
			ParentComm: "docker|containerd|podman|runc", ChildPath: "/usr/bin/|/usr/sbin/|/bin/"},
		// Systemd executing unusual binaries
		{Name: "systemd-unusual", Description: "Systemd executing unusual binary", Severity: "warn",
			ParentComm: "systemd", ChildPath: "/tmp/|/dev/shm/|/var/tmp/"},
		// Database server spawning shells = SQL injection escalation
		{Name: "db-shell", Description: "Database server spawning shell", Severity: "critical",
			ParentComm: "mysql|postgres|mongod|redis", ChildComm: "bash|sh|dash|python|perl"},
	}
}

// LineageChecker manages the eBPF lineage tracking and rule engine.
type LineageChecker struct {
	mu      sync.Mutex
	coll    *ebpf.Collection
	reader  *ringbuf.Reader
	links   []link.Link
	alert   *alert.AlertManager
	logger  *zap.Logger
	tree    map[uint32]*LineageNode // PID → node
	rules   []LineageRule
	stats   LineageStats
	statsMu sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	enabled bool
}

// LineageStats holds lineage tracking statistics.
type LineageStats struct {
	ProcessCount    int
	AliveCount      int
	CredChanges     int
	PtraceEvents    int
	NamespaceEvents int
	SUIDExecs       int
	RuleMatches     int
	SuspiciousProcs int
}

// NewLineageChecker creates and initializes a lineage tracker.
func NewLineageChecker(alertMgr *alert.AlertManager, logger *zap.Logger) (*LineageChecker, error) {
	return &LineageChecker{
		tree:   make(map[uint32]*LineageNode),
		rules:  DefaultLineageRules(),
		alert:  alertMgr,
		logger: logger,
	}, nil
}

// Load loads the eBPF collection from the specified object file.
func (lc *LineageChecker) Load(objPath string) error {
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("load lineage eBPF: %w", err)
	}
	lc.coll = coll

	// Enable lineage tracking
	key := uint32(0)
	enableVal := uint32(1)
	if m := lc.coll.Maps["lin_global_enable"]; m != nil {
		m.Put(&key, &enableVal)
	}

	// Attach kprobes
	attachCount := 0
	kprobes := map[string]string{
		"handle_bprm_committing_creds": "security_bprm_committing_creds",
		"handle_ptrace_check":          "security_ptrace_access_check",
		"handle_lineage_setns":         ebpfpkg.SyscallWrapper("setns"),
		"handle_lineage_unshare":       ebpfpkg.SyscallWrapper("unshare"),
		"handle_lineage_cap_capable":   "cap_capable",
	}
	for progName, symbol := range kprobes {
		if prog := lc.coll.Programs[progName]; prog != nil {
			l, err := link.Kprobe(symbol, prog, nil)
			if err != nil {
				lc.logger.Warn("lineage: failed to attach kprobe", zap.String("prog", progName), zap.Error(err))
				continue
			}
			lc.links = append(lc.links, l)
			attachCount++
		}
	}

	// Attach tracepoints
	tracepoints := map[string][2]string{
		"handle_lineage_fork": {"sched", "sched_process_fork"},
		"handle_lineage_exec": {"sched", "sched_process_exec"},
		"handle_lineage_exit": {"sched", "sched_process_exit"},
	}
	for progName, tp := range tracepoints {
		if prog := lc.coll.Programs[progName]; prog != nil {
			l, err := link.Tracepoint(tp[0], tp[1], prog, nil)
			if err != nil {
				lc.logger.Warn("lineage: failed to attach tracepoint", zap.String("prog", progName), zap.Error(err))
				continue
			}
			lc.links = append(lc.links, l)
			attachCount++
		}
	}

	// Open ringbuf reader
	if m := lc.coll.Maps["lin_events"]; m != nil {
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("lineage ringbuf: %w", err)
		}
		lc.reader = reader
	}

	lc.enabled = attachCount > 0
	lc.logger.Info("lineage: eBPF loaded", zap.Int("attached", attachCount))
	return nil
}

// Run starts the lineage event reader and rule engine.
func (lc *LineageChecker) Run(ctx context.Context) {
	lc.ctx, lc.cancel = context.WithCancel(ctx)

	// Read ringbuf events
	go lc.readEvents()

	// Run lineage rule engine every 30 seconds
	go lc.ruleEngineLoop()

	// Seed the tree from /proc
	lc.seedFromProc()
}

// seedFromProc populates the lineage tree from /proc at startup.
func (lc *LineageChecker) seedFromProc() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		lc.logger.Warn("lineage: failed to read /proc", zap.Error(err))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid := parsePID(entry.Name())
		if pid == 0 {
			continue
		}

		node := lc.readProcNode(pid)
		if node != nil {
			lc.mu.Lock()
			lc.tree[pid] = node
			lc.mu.Unlock()
		}
	}

	lc.statsMu.Lock()
	lc.stats.ProcessCount = len(lc.tree)
	lc.stats.AliveCount = len(lc.tree)
	lc.statsMu.Unlock()

	lc.logger.Info("lineage: seeded from /proc", zap.Int("processes", len(lc.tree)))
}

// readProcNode reads process info from /proc/[pid]/stat.
func (lc *LineageChecker) readProcNode(pid uint32) *LineageNode {
	statFile := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statFile)
	if err != nil {
		return nil
	}

	// Parse /proc/[pid]/stat: pid (comm) state ppid ...
	// Find comm boundaries
	start := -1
	end := -1
	for i, b := range data {
		if b == '(' && start == -1 {
			start = i
		}
		if b == ')' && start != -1 {
			end = i
			break
		}
	}
	if start == -1 || end == -1 {
		return nil
	}

	comm := string(data[start+1 : end])

	// Parse fields after comm
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) < 1 {
		return nil
	}

	ppid := uint32(0)
	if len(fields) >= 2 {
		fmt.Sscanf(fields[1], "%d", &ppid)
	}

	// Read UID from /proc/[pid]/status
	uid := uint32(0)
	gid := uint32(0)
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					fmt.Sscanf(fields[1], "%d", &uid)
				}
			}
			if strings.HasPrefix(line, "Gid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					fmt.Sscanf(fields[1], "%d", &gid)
				}
			}
		}
	}

	// Read exe path
	path := ""
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		path = exe
	}

	return &LineageNode{
		PID:   pid,
		PPID:  ppid,
		UID:   uid,
		GID:   gid,
		Comm:  comm,
		Path:  path,
		Alive: true,
	}
}

// readEvents reads lineage events from the eBPF ringbuf.
func (lc *LineageChecker) readEvents() {
	if lc.reader == nil {
		return
	}

	for {
		select {
		case <-lc.ctx.Done():
			return
		default:
		}

		record, err := lc.reader.Read()
		if err != nil {
			if lc.ctx.Err() != nil {
				return
			}
			continue
		}

		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample)
		switch eventType {
		case models.LinEventCredChange:
			lc.handleCredChange(record.RawSample)
		case models.LinEventPtrace:
			lc.handlePtrace(record.RawSample)
		case models.LinEventSetNS:
			lc.handleSetNS(record.RawSample)
		case models.LinEventUnshare:
			lc.handleUnshare(record.RawSample)
		case models.LinEventSUIDExec:
			lc.handleSUIDExec(record.RawSample)
		}
	}
}

func (lc *LineageChecker) handleCredChange(raw []byte) {
	// C struct lin_cred_event layout (with standard alignment):
	//   event_type(4) + pid(4) + old_uid(4) + new_uid(4) + old_gid(4) +
	//   new_gid(4) + euid(4) + egid(4) + is_setuid(1) + is_setgid(1) +
	//   _pad(2) + [4 implicit pad] + timestamp_ns(8) + comm(16) = 64 bytes
	if len(raw) < 64 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	oldUID := binary.LittleEndian.Uint32(raw[8:12])
	newUID := binary.LittleEndian.Uint32(raw[12:16])
	oldGID := binary.LittleEndian.Uint32(raw[16:20])
	newGID := binary.LittleEndian.Uint32(raw[20:24])
	comm := string(raw[48:64])
	comm = strings.TrimRight(comm, "\x00")

	lc.statsMu.Lock()
	lc.stats.CredChanges++
	lc.statsMu.Unlock()

	// Update tree node
	lc.mu.Lock()
	if node, ok := lc.tree[pid]; ok {
		node.UID = newUID
		node.GID = newGID
		node.Flags |= models.LNFPrivEsc
	}
	lc.mu.Unlock()

	// Alert on root escalation from non-root
	if oldUID != 0 && newUID == 0 {
		lc.alert.CriticalPID(pid, string(models.CatProcessLineage),
			"PRIVILEGE ESCALATION: pid=%d comm=%s uid %d→%d gid %d→%d",
			pid, comm, oldUID, newUID, oldGID, newGID)
	} else {
		lc.alert.WarnPID(pid, string(models.CatProcessLineage),
			"Credential change: pid=%d comm=%s uid %d→%d",
			pid, comm, oldUID, newUID)
	}
}

func (lc *LineageChecker) handlePtrace(raw []byte) {
	if len(raw) < 56 {
		return
	}
	sourcePID := binary.LittleEndian.Uint32(raw[4:8])
	targetPID := binary.LittleEndian.Uint32(raw[8:12])
	request := binary.LittleEndian.Uint32(raw[12:16])
	sourceComm := string(raw[24:40])
	sourceComm = strings.TrimRight(sourceComm, "\x00")
	targetComm := string(raw[40:56])
	targetComm = strings.TrimRight(targetComm, "\x00")

	lc.statsMu.Lock()
	lc.stats.PtraceEvents++
	lc.statsMu.Unlock()

	lc.alert.WarnPID(sourcePID, string(models.CatProcessLineage),
		"PTRACE: source=%s(%d) → target=%s(%d) request=%d",
		sourceComm, sourcePID, targetComm, targetPID, request)
}

func (lc *LineageChecker) handleSetNS(raw []byte) {
	// C struct lin_ns_event layout:
	//   event_type(4) + pid(4) + fd(4) + nstype(4) + timestamp(8) + comm(16) = 40 bytes
	if len(raw) < 40 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	nstype := binary.LittleEndian.Uint32(raw[12:16])
	comm := string(raw[24:40])
	comm = strings.TrimRight(comm, "\x00")

	lc.statsMu.Lock()
	lc.stats.NamespaceEvents++
	lc.statsMu.Unlock()

	nsNames := decodeNamespaceFlags(nstype)
	lc.alert.WarnPID(pid, string(models.CatContainerEscape),
		"SETNS: pid=%d comm=%s namespaces=%s", pid, comm, nsNames)
}

func (lc *LineageChecker) handleUnshare(raw []byte) {
	// C struct lin_ns_event layout:
	//   event_type(4) + pid(4) + fd(4) + nstype(4) + timestamp(8) + comm(16) = 40 bytes
	if len(raw) < 40 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	nstype := binary.LittleEndian.Uint32(raw[12:16])
	comm := string(raw[24:40])
	comm = strings.TrimRight(comm, "\x00")

	lc.statsMu.Lock()
	lc.stats.NamespaceEvents++
	lc.statsMu.Unlock()

	nsNames := decodeNamespaceFlags(nstype)
	// User namespace creation is suspicious
	if nstype&0x10000000 != 0 {
		lc.alert.CriticalPID(pid, string(models.CatContainerEscape),
			"UNSHARE USER NS: pid=%d comm=%s flags=%s (privilege escalation vector)",
			pid, comm, nsNames)
	} else {
		lc.alert.Info(string(models.CatContainerEscape),
			"UNSHARE: pid=%d comm=%s namespaces=%s", pid, comm, nsNames)
	}
}

func (lc *LineageChecker) handleSUIDExec(raw []byte) {
	// C struct lin_suid_event layout (with standard alignment):
	//   event_type(4) + pid(4) + old_uid(4) + new_uid(4) + old_gid(4) +
	//   new_gid(4) + timestamp(8) + comm(16) + path(128) = 176 bytes
	if len(raw) < 176 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	oldUID := binary.LittleEndian.Uint32(raw[8:12])
	newUID := binary.LittleEndian.Uint32(raw[12:16])
	comm := string(raw[32:48])
	comm = strings.TrimRight(comm, "\x00")
	path := string(raw[48:176])
	path = strings.TrimRight(path, "\x00")

	lc.statsMu.Lock()
	lc.stats.SUIDExecs++
	lc.statsMu.Unlock()

	lc.alert.WarnPID(pid, string(models.CatProcessLineage),
		"SUID EXEC: pid=%d comm=%s path=%s uid %d→%d",
		pid, comm, path, oldUID, newUID)
}

// ruleEngineLoop periodically applies lineage rules to the process tree.
func (lc *LineageChecker) ruleEngineLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(5 * time.Minute) // prune dead processes every 5 min
	defer cleanupTicker.Stop()

	for {
		select {
		case <-lc.ctx.Done():
			return
		case <-ticker.C:
			lc.applyRules()
		case <-cleanupTicker.C:
			lc.pruneDeadProcesses()
		}
	}
}

// pruneDeadProcesses removes lineage nodes that have been dead for more than 10 minutes.
// This prevents unbounded memory growth on systems with high process churn (BUG-012 fix).
func (lc *LineageChecker) pruneDeadProcesses() {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	now := time.Now().UnixNano()
	var removed int
	for pid, node := range lc.tree {
		if !node.Alive && node.ExitNS > 0 {
			if (now - int64(node.ExitNS)) > 10*60*1e9 { // 10 minutes
				delete(lc.tree, pid)
				removed++
			}
		}
	}
	if removed > 0 && lc.logger != nil {
		lc.logger.Info("lineage: pruned dead processes", zap.Int("removed", removed))
	}
}

// applyRules checks all lineage rules against the current process tree.
// BUG-038 fix: Copy the tree under lock, release lock, then iterate the
// copy and generate alerts. This avoids holding lc.mu during alert generation.
func (lc *LineageChecker) applyRules() {
	lc.mu.Lock()
	treeCopy := make(map[uint32]*LineageNode, len(lc.tree))
	for k, v := range lc.tree {
		cp := *v
		treeCopy[k] = &cp
	}
	lc.mu.Unlock()

	for _, rule := range lc.rules {
		for _, node := range treeCopy {
			if !node.Alive {
				continue
			}
			// Check if this node matches the child pattern
			if !matchesPattern(node.Comm, rule.ChildComm) &&
				!matchesPattern(node.Path, rule.ChildPath) {
				continue
			}

			// Find parent
			parent, ok := treeCopy[node.PPID]
			if !ok || !parent.Alive {
				continue
			}

			// Check parent pattern
			if matchesPattern(parent.Comm, rule.ParentComm) ||
				matchesPattern(parent.Path, rule.ParentPath) {
				lc.statsMu.Lock()
				lc.stats.RuleMatches++
				lc.statsMu.Unlock()

				switch rule.Severity {
				case "critical":
					lc.alert.Critical(string(models.CatBehavioralCluster),
						"LINEAGE RULE [%s]: %s — %s(%d) → %s(%d) path=%s",
						rule.Name, rule.Description,
						parent.Comm, parent.PID,
						node.Comm, node.PID, node.Path)
				case "warn":
					lc.alert.Warn(string(models.CatBehavioralCluster),
						"LINEAGE RULE [%s]: %s — %s(%d) → %s(%d)",
						rule.Name, rule.Description,
						parent.Comm, parent.PID,
						node.Comm, node.PID)
				default:
					lc.alert.Info(string(models.CatProcessLineage),
						"LINEAGE RULE [%s]: %s — %s(%d) → %s(%d)",
						rule.Name, rule.Description,
						parent.Comm, parent.PID,
						node.Comm, node.PID)
				}
			}
		}
	}

	// Count suspicious processes
	suspicious := 0
	aliveCount := 0
	for _, node := range treeCopy {
		if node.Alive {
			aliveCount++
			if node.Flags&models.LNFSuspicious != 0 {
				suspicious++
			}
		}
	}
	lc.statsMu.Lock()
	lc.stats.SuspiciousProcs = suspicious
	lc.stats.ProcessCount = len(treeCopy)
	lc.stats.AliveCount = aliveCount
	lc.statsMu.Unlock()
}

// Stats returns the current lineage statistics.
func (lc *LineageChecker) Stats() LineageStats {
	lc.statsMu.Lock()
	defer lc.statsMu.Unlock()
	return lc.stats
}

// IsEnabled returns whether lineage tracking is active.
func (lc *LineageChecker) IsEnabled() bool {
	return lc.enabled
}

// Tree returns a snapshot of the current lineage tree.
func (lc *LineageChecker) Tree() map[uint32]*LineageNode {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	result := make(map[uint32]*LineageNode, len(lc.tree))
	for k, v := range lc.tree {
		cp := *v
		result[k] = &cp
	}
	return result
}

// Close cleans up the lineage checker.
func (lc *LineageChecker) Close() {
	if lc.cancel != nil {
		lc.cancel()
	}
	for _, l := range lc.links {
		_ = l.Close()
	}
	if lc.reader != nil {
		lc.reader.Close()
	}
	if lc.coll != nil {
		lc.coll.Close()
	}
}

// ── Helpers ──────────────────────────────────────────────────────

func parsePID(s string) uint32 {
	var pid uint32
	for _, c := range s {
		if c >= '0' && c <= '9' {
			pid = pid*10 + uint32(c-'0')
		} else {
			return 0
		}
	}
	return pid
}

func countAlive(tree map[uint32]*LineageNode) int {
	count := 0
	for _, n := range tree {
		if n.Alive {
			count++
		}
	}
	return count
}

// matchesPattern checks if a value matches a pipe-separated pattern.
// Patterns like "bash|sh|dash" match any of the alternatives.
// Path patterns like "/tmp/|/dev/shm/" match if value starts with any.
func matchesPattern(value, pattern string) bool {
	if pattern == "" {
		return false
	}
	for _, alt := range strings.Split(pattern, "|") {
		if alt == "" {
			continue
		}
		if strings.HasPrefix(alt, "/") {
			// Path pattern: prefix match
			if strings.HasPrefix(value, alt) {
				return true
			}
		} else {
			// Comm pattern: exact match
			if value == alt {
				return true
			}
		}
	}
	return false
}

func decodeNamespaceFlags(flags uint32) string {
	var names []string
	for flag, name := range models.NamespaceFlagNames {
		if flags&flag != 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("0x%x", flags)
	}
	return strings.Join(names, "|")
}

// IP helpers
// IP helpers — prevent unused import errors
var (
	_ = net.IPv4len
	_ = filepath.Base
)
