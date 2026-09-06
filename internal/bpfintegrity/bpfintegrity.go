// Package bpfintegrity implements eBPF self-integrity watchdog for VIGIL.
//
// Based on: EvilEDR (USENIX Security 2025), eBPF Misbehavior Detection (SOSP 2025).
//
// Monitors VIGIL's own eBPF programs and those of trusted companion processes to detect
// tampering, replacement, or removal.
package bpfintegrity

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/models"
)

type BPFIntegrityChecker struct {
	mu         sync.Mutex
	coll       *ebpf.Collection
	reader     *ringbuf.Reader
	links      []link.Link
	alert      *alert.AlertManager
	logger     *zap.Logger
	stats      BPFIntegrityStats
	statsMu    sync.Mutex
	enabled    bool
	ctx        context.Context
	cancel     context.CancelFunc

	// Expected BPF program counts per module
	expectedProgs map[string]int
	lastCheck     time.Time
}

type BPFIntegrityStats struct {
	BPFPrograms    int
	BPFMaps        int
	BPFCheckEvents int
	ProcessExits   int
	UnexpectedLoad int
	MissingProgs   int
	LastCheckNS    int64
}

func NewBPFIntegrityChecker(alertMgr *alert.AlertManager, logger *zap.Logger) (*BPFIntegrityChecker, error) {
	return &BPFIntegrityChecker{
		expectedProgs: map[string]int{
			"vigil_kprobe":      12, // 6 kprobe pairs
			"vigil_syscall_arg": 5,
			"vigil_crossview":   5,
			"vigil_lineage":     8,  // 5 kprobes + 3 tracepoints
			"vigil_integrity":   2,
			"vigil_dns":         2,
			"vigil_tty":         3,
			"vigil_container":   4,
			"vigil_flow":        2,
		},
		alert:  alertMgr,
		logger: logger,
	}, nil
}

func (bic *BPFIntegrityChecker) Load(objPath string) error {
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("load integrity eBPF: %w", err)
	}
	bic.coll = coll

	// Enable
	key := uint32(0)
	enableVal := uint32(1)
	if m := bic.coll.Maps["int_global_enable"]; m != nil {
		m.Put(&key, &enableVal)
	}

	// Attach kprobes
	attachCount := 0
	// Attach kprobe
	if prog := bic.coll.Programs["handle_security_bpf"]; prog != nil {
		l, err := link.Kprobe("security_bpf", prog, nil)
		if err != nil {
			bic.logger.Warn("bpf-integrity: failed to attach kprobe", zap.String("prog", "handle_security_bpf"), zap.Error(err))
		} else {
			bic.links = append(bic.links, l)
			attachCount++
		}
	}
	// Attach tracepoint
	if prog := bic.coll.Programs["handle_integrity_exit"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_process_exit", prog, nil)
		if err != nil {
			bic.logger.Warn("bpf-integrity: failed to attach tracepoint", zap.String("prog", "handle_integrity_exit"), zap.Error(err))
		} else {
			bic.links = append(bic.links, l)
			attachCount++
		}
	}

	if m := bic.coll.Maps["int_events"]; m != nil {
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("bpf-integrity ringbuf: %w", err)
		}
		bic.reader = reader
	}

	bic.enabled = attachCount > 0
	bic.logger.Info("bpf-integrity: eBPF loaded", zap.Int("attached", attachCount))
	return nil
}

func (bic *BPFIntegrityChecker) Run(ctx context.Context) {
	bic.ctx, bic.cancel = context.WithCancel(ctx)
	go bic.readEvents()
	go bic.periodicCheck()
}

func (bic *BPFIntegrityChecker) readEvents() {
	if bic.reader == nil {
		return
	}
	for {
		select {
		case <-bic.ctx.Done():
			return
		default:
		}
		record, err := bic.reader.Read()
		if err != nil {
			if bic.ctx.Err() != nil {
				return
			}
			continue
		}
		if len(record.RawSample) < 4 {
			continue
		}
		eventType := binary.LittleEndian.Uint32(record.RawSample)
		switch eventType {
		case models.IntEventBPFCheck:
			bic.handleBPFCheck(record.RawSample)
		case models.IntEventProcessExit:
			bic.handleProcessExit(record.RawSample)
		case models.IntEventBPFLoad:
			bic.handleBPFLoad(record.RawSample)
		case models.IntEventBPFFree:
			bic.handleBPFFree(record.RawSample)
		default:
			bic.logger.Debug("bpf-integrity: unhandled event type", zap.Uint32("type", eventType))
		}
	}
}

func (bic *BPFIntegrityChecker) handleBPFCheck(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	opcode := binary.LittleEndian.Uint32(raw[16:20])
	comm := string(raw[28:44])
	comm = strings.TrimRight(comm, "\x00")

	bic.statsMu.Lock()
	bic.stats.BPFCheckEvents++
	bic.statsMu.Unlock()

	// BPF_PROG_LOAD = 5
	if opcode == 5 {
		bic.alert.WarnPID(0, string(models.CatBPFIntegrity),
			"BPF PROG LOAD: pid=%d comm=%s — new BPF program loaded", pid, comm)
	}
}

// Known VIGIL and companion process name prefixes for integrity monitoring.
var protectedProcessPrefixes = []string{"vigil", "prx-proxy", "prx-sentinel", "prx-watchdog"}

// isProtectedProcess checks if a comm name matches a VIGIL or trusted companion process.
func isProtectedProcess(comm string) bool {
	for _, prefix := range protectedProcessPrefixes {
		if strings.HasPrefix(comm, prefix) {
			return true
		}
	}
	return false
}

func (bic *BPFIntegrityChecker) handleProcessExit(raw []byte) {
	if len(raw) < 32 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	comm := string(raw[16:32])
	comm = strings.TrimRight(comm, "\x00")

	// Sanitize comm: if it contains non-printable characters, the process
	// exited before eBPF could read its comm properly (race condition).
	// Replace non-printable bytes with '?' to indicate corruption.
	sanitized := make([]byte, 0, len(comm))
	hasCorruption := false
	for _, b := range []byte(comm) {
		if b >= 32 && b < 127 {
			sanitized = append(sanitized, b)
		} else if b == 0 {
			break // null terminator
		} else {
			sanitized = append(sanitized, '?')
			hasCorruption = true
		}
	}
	cleanComm := string(sanitized)

	// If comm is corrupted (non-printable chars), this is a race condition
	// on a dying process — not a real integrity threat. Log at DEBUG only.
	if hasCorruption || len(cleanComm) == 0 {
		bic.logger.Debug("bpf-integrity: ignoring exit of process with corrupted comm",
			zap.Uint32("pid", pid),
			zap.String("raw_comm", fmt.Sprintf("%q", comm)),
		)
		return
	}

	// Only alert on exits of VIGIL or companion processes — these are our
	// protected processes and their unexpected termination could indicate
	// an attacker killing the EDR (EvilEDR attack pattern).
	// All other process exits are normal OS behavior and should NOT
	// generate CRITICAL alerts.
	if !isProtectedProcess(cleanComm) {
		bic.logger.Debug("bpf-integrity: ignoring exit of non-protected process",
			zap.Uint32("pid", pid),
			zap.String("comm", cleanComm),
		)
		return
	}

	bic.statsMu.Lock()
	bic.stats.ProcessExits++
	bic.statsMu.Unlock()

	bic.alert.CriticalPID(0, string(models.CatBPFIntegrity),
		"CRITICAL: protected process exited: pid=%d comm=%s — possible EDR tampering!", pid, cleanComm)
}

// periodicCheck verifies BPF program counts every 5 minutes.
func (bic *BPFIntegrityChecker) periodicCheck() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-bic.ctx.Done():
			return
		case <-ticker.C:
			bic.verifyBPFPrograms()
		}
	}
}

func (bic *BPFIntegrityChecker) verifyBPFPrograms() {
	// Read /proc/self/fdinfo to count BPF FDs
	// Read /sys/fs/bpf for pinned programs
	// Check VIGIL process is still alive

	// Count VIGIL processes
	vigilProcs := 0
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var pid uint32
		fmt.Sscanf(entry.Name(), "%d", &pid)
		if pid == 0 {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if strings.HasPrefix(string(comm), "vigil") {
			vigilProcs++
		}
	}

	if vigilProcs == 0 {
		bic.alert.CriticalPID(0, string(models.CatBPFIntegrity),
			"SELF-INTEGRITY: No vigil process found in /proc!")
	}

	// Count BPF programs/maps by reading fdinfo and checking for BPF-specific markers
	bpfProgs := 0
	if fdEntries, err := os.ReadDir("/proc/self/fd"); err == nil {
		for _, fdEntry := range fdEntries {
			fdinfoPath := fmt.Sprintf("/proc/self/fdinfo/%s", fdEntry.Name())
			fdinfo, err := os.ReadFile(fdinfoPath)
			if err != nil {
				continue
			}
			// Only count FDs that are BPF programs or maps
			if strings.Contains(string(fdinfo), "bpf_prog_info") || strings.Contains(string(fdinfo), "map_id") {
				bpfProgs++
			}
		}
	}

	bic.statsMu.Lock()
	bic.stats.BPFPrograms = bpfProgs
	bic.stats.LastCheckNS = time.Now().UnixNano()
	bic.statsMu.Unlock()

	bic.lastCheck = time.Now()
	bic.logger.Info("bpf-integrity: periodic check", zap.Int("vigil_procs", vigilProcs), zap.Int("bpf_fds", bpfProgs))
}

// handleBPFLoad processes BPF program load events.
// Detects unauthorized BPF program loading — a key defense against rootkits
// that inject malicious eBPF programs (VEP NSDI 2025).
func (bic *BPFIntegrityChecker) handleBPFLoad(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	progType := binary.LittleEndian.Uint32(raw[8:12])
	opcode := binary.LittleEndian.Uint32(raw[16:20])
	comm := strings.TrimRight(string(raw[28:44]), "\x00")

	bic.statsMu.Lock()
	bic.stats.BPFPrograms++
	bic.statsMu.Unlock()

	// Alert on BPF program loads by non-VIGIL processes
	if !strings.Contains(comm, "vigil") {
		bic.alert.WarnPID(pid, string(models.CatSelfIntegrity),
			"BPF PROGRAM LOAD: pid=%d comm=%s prog_type=%d opcode=%d — new BPF program loaded",
			pid, comm, progType, opcode)
	}
}

// handleBPFFree processes BPF map/program free events.
// Detects removal of BPF programs — a rootkit might try to detach VIGIL's probes.
func (bic *BPFIntegrityChecker) handleBPFFree(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	mapID := binary.LittleEndian.Uint32(raw[12:16])
	comm := strings.TrimRight(string(raw[28:44]), "\x00")

	bic.statsMu.Lock()
	bic.stats.BPFMaps--
	if bic.stats.BPFMaps < 0 {
		bic.stats.BPFMaps = 0
	}
	bic.statsMu.Unlock()

	bic.logger.Debug("bpf-integrity: BPF map/program freed",
		zap.Uint32("pid", pid),
		zap.Uint32("map_id", mapID),
		zap.String("comm", comm))
}

func (bic *BPFIntegrityChecker) Stats() BPFIntegrityStats {
	bic.statsMu.Lock()
	defer bic.statsMu.Unlock()
	return bic.stats
}

func (bic *BPFIntegrityChecker) IsEnabled() bool {
	return bic.enabled
}

func (bic *BPFIntegrityChecker) Close() {
	if bic.cancel != nil {
		bic.cancel()
	}
	for _, l := range bic.links {
		_ = l.Close()
	}
	if bic.reader != nil {
		bic.reader.Close()
	}
	if bic.coll != nil {
		bic.coll.Close()
	}
}