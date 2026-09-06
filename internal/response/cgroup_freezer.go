package response

// Cgroup v2 Freezer — non-destructive process containment.
//
// Academic basis:
//   - bpfbox (CCSW 2020): eBPF-based process confinement using cgroup isolation
//   - cgroup v2 freezer (kernel 4.5+, Roman Gushchin): cgroup.freeze interface
//     Writes "1" to cgroup.freeze → all tasks in cgroup enter TASK_UNINTERRUPTIBLE
//     Unlike SIGSTOP: no signal delivery, no ptrace interference, reversible, no resource leak
//   - CryptoGuard (AsiaCCS 2025): Process freeze as immediate containment before analysis
//   - eBPF-Shield (SOCA 2026): Graduated remediation — freeze before kill

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const (
	// VIGIL cgroup path under cgroup v2 root
	vigilCgroupPath = "vigil-quarantine"
	// cgroup v2 root mount point
	cgroupV2Root = "/sys/fs/cgroup"
)

type CgroupFreezer struct {
	mu      sync.Mutex
	logger  *zap.Logger
	frozen  map[uint32]string // pid → cgroup path
}

func NewCgroupFreezer(logger *zap.Logger) *CgroupFreezer {
	return &CgroupFreezer{
		logger: logger,
		frozen: make(map[uint32]string),
	}
}

// Freeze moves a process into a VIGIL quarantine cgroup and freezes it.
// This is NON-DESTRUCTIVE — the process can be thawed and resumed.
func (f *CgroupFreezer) Freeze(pid uint32) (ResponseStatus, string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Skip if already frozen
	if _, ok := f.frozen[pid]; ok {
		return StatusExecuted, fmt.Sprintf("pid %d already frozen", pid)
	}

	// Verify process exists
	if _, err := os.FindProcess(int(pid)); err != nil {
		return StatusFailed, fmt.Sprintf("find process %d: %v", pid, err)
	}

	// Create per-process quarantine cgroup
	cgroupName := fmt.Sprintf("vigil-frozen-%d", pid)
	cgroupPath := filepath.Join(cgroupV2Root, vigilCgroupPath, cgroupName)

	// Create cgroup directory (kernel auto-creates cgroup files)
	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return StatusFailed, fmt.Sprintf("create cgroup %s: %v", cgroupPath, err)
	}

	// Enable freezer controller in the cgroup
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.subtree_control"), []byte("+freezer"), 0); err != nil {
		// Try parent subtree_control
		parentSubtree := filepath.Join(cgroupV2Root, vigilCgroupPath, "cgroup.subtree_control")
		_ = os.WriteFile(parentSubtree, []byte("+freezer"), 0)
	}

	// Move process into the cgroup (write PID to cgroup.procs)
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(fmt.Sprintf("%d", pid)), 0); err != nil {
		// Cleanup: remove the cgroup directory
		os.Remove(cgroupPath)
		return StatusFailed, fmt.Sprintf("move pid %d to cgroup: %v", pid, err)
	}

	// Freeze the cgroup (write "1" to cgroup.freeze)
	freezeFile := filepath.Join(cgroupPath, "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("1"), 0); err != nil {
		// If freezer not available, process is isolated but not frozen
		f.logger.Warn("cgroup freezer not available, process isolated but not frozen",
			zap.Uint32("pid", pid),
			zap.Error(err),
		)
		f.frozen[pid] = cgroupPath
		return StatusExecuted, fmt.Sprintf("pid %d moved to quarantine cgroup (freeze unavailable, isolated only)", pid)
	}

	// Verify frozen state
	freezeState, err := os.ReadFile(freezeFile)
	if err == nil && strings.TrimSpace(string(freezeState)) == "1" {
		f.frozen[pid] = cgroupPath
		f.logger.Info("cgroup freezer: process frozen",
			zap.Uint32("pid", pid),
			zap.String("cgroup", cgroupPath),
		)
		return StatusExecuted, fmt.Sprintf("pid %d frozen via cgroup v2 freezer", pid)
	}

	f.frozen[pid] = cgroupPath
	return StatusExecuted, fmt.Sprintf("pid %d quarantined (freeze state uncertain)", pid)
}

// Thaw unfreezes a process and moves it back to the root cgroup.
func (f *CgroupFreezer) Thaw(pid uint32) (ResponseStatus, string) {
	f.mu.Lock()
	cgroupPath, ok := f.frozen[pid]
	if ok {
		delete(f.frozen, pid)
	}
	f.mu.Unlock()

	if !ok {
		return StatusFailed, fmt.Sprintf("pid %d not frozen", pid)
	}

	// Unfreeze the cgroup
	freezeFile := filepath.Join(cgroupPath, "cgroup.freeze")
	if err := os.WriteFile(freezeFile, []byte("0"), 0); err != nil {
		return StatusFailed, fmt.Sprintf("unfreeze pid %d: %v", pid, err)
	}

	// Move process back to root cgroup
	rootProcs := filepath.Join(cgroupV2Root, "cgroup.procs")
	if err := os.WriteFile(rootProcs, []byte(fmt.Sprintf("%d", pid)), 0); err != nil {
		f.logger.Warn("failed to move process back to root cgroup",
			zap.Uint32("pid", pid),
			zap.Error(err),
		)
	}

	// Remove the quarantine cgroup
	if err := os.Remove(cgroupPath); err != nil {
		f.logger.Warn("failed to remove quarantine cgroup",
			zap.String("cgroup", cgroupPath),
			zap.Error(err),
		)
	}

	f.logger.Info("cgroup freezer: process thawed", zap.Uint32("pid", pid))
	return StatusExecuted, fmt.Sprintf("pid %d thawed and restored", pid)
}

// IsFrozen checks if a PID is currently frozen by VIGIL.
func (f *CgroupFreezer) IsFrozen(pid uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.frozen[pid]
	return ok
}

// FrozenPIDs returns all currently frozen PIDs.
func (f *CgroupFreezer) FrozenPIDs() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	pids := make([]uint32, 0, len(f.frozen))
	for pid := range f.frozen {
		pids = append(pids, pid)
	}
	return pids
}

// Init ensures the VIGIL quarantine cgroup hierarchy exists.
func (f *CgroupFreezer) Init() error {
	// Check if freezer controller is available
	controllers, err := os.ReadFile(filepath.Join(cgroupV2Root, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read cgroup.controllers: %w", err)
	}
	if !strings.Contains(string(controllers), "freezer") {
		f.logger.Warn("cgroup freezer: 'freezer' controller not available in cgroup.controllers",
			zap.String("controllers", strings.TrimSpace(string(controllers))),
		)
		return fmt.Errorf("cgroup freezer controller not available: freezer not listed in %s/cgroup.controllers", cgroupV2Root)
	}

	vigilCgroup := filepath.Join(cgroupV2Root, vigilCgroupPath)
	if err := os.MkdirAll(vigilCgroup, 0755); err != nil {
		return fmt.Errorf("create vigil cgroup: %w", err)
	}

	// Enable freezer controller in the parent cgroup
	subtreeFile := filepath.Join(cgroupV2Root, "cgroup.subtree_control")
	_ = os.WriteFile(subtreeFile, []byte("+freezer"), 0)

	f.logger.Info("cgroup freezer: initialized", zap.String("path", vigilCgroup))
	return nil
}