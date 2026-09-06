package response

// Evidence Capture — forensic state preservation before response actions.
//
// Academic basis:
//   - GuardFS (arXiv 2401.17917): Data extraction before file access — capture state before mitigation
//   - CryptoGuard (AsiaCCS 2025): Two-phase — detect first, then contain+preserve for analysis
//   - EvilEDR (USENIX 2025): EDR actions destroy evidence — always capture BEFORE acting
//   - Standard IR practice: Order of Volatility — capture /proc (volatile) before disk
//
// Captures: /proc/[pid]/cmdline, environ, maps, fd/, status, exe, cgroup, stack, wchan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type EvidenceCapture struct {
	evidenceDir string
	logger      *zap.Logger
}

func NewEvidenceCapture(evidenceDir string, logger *zap.Logger) *EvidenceCapture {
	if evidenceDir == "" {
		evidenceDir = "/var/lib/vigil/evidence"
	}
	return &EvidenceCapture{
		evidenceDir: evidenceDir,
		logger:     logger,
	}
}

// Capture preserves forensic state of a process by copying /proc entries.
// This MUST be the first response action for any alert (EvilEDR defense).
func (e *EvidenceCapture) Capture(pid uint32, attackType AttackType) (ResponseStatus, string) {
	// Create evidence directory for this capture
	timestamp := time.Now().Format("20060102-150405")
	// Capture is safe — pid is uint32, timestamp is fixed format, attackType is from constants
	// Sanitize attackType to prevent path traversal
	safeAttack := strings.ReplaceAll(string(attackType), "/", "_")
	safeAttack = strings.ReplaceAll(safeAttack, "..", "_")
	evidencePath := filepath.Join(e.evidenceDir, fmt.Sprintf("pid-%d-%s-%s", pid, safeAttack, timestamp))
	// Verify result is within evidenceDir
	if !strings.HasPrefix(evidencePath, e.evidenceDir) {
		return StatusFailed, "path traversal detected in attack type"
	}

	if err := os.MkdirAll(evidencePath, 0700); err != nil {
		return StatusFailed, fmt.Sprintf("create evidence dir: %v", err)
	}

	procDir := fmt.Sprintf("/proc/%d", pid)
	captured := 0
	failed := 0

	// Files to capture (order of volatility)
	procFiles := []string{
		"cmdline",    // Command line arguments
		"environ",    // Environment variables
		"maps",       // Memory map (loaded libraries, regions)
		"status",     // Process status (UID, GID, caps, threads)
		"cgroup",     // Cgroup membership
		"stack",      // Kernel stack trace
		"wchan",      // Wait channel function
		"stat",       // Process statistics
		"statm",      // Memory statistics
		"io",         // I/O statistics
		"oom_score",  // OOM killer score
		"oom_adj",    // OOM adjustment
		"coredump_filter", // Core dump settings
		"personality", // Process personality (address space layout)
		"comm",       // Process command name
		"sessionid",  // Session ID
		"loginuid",   // Login UID (AUDITLEUID)
	}

	// Capture individual files
	for _, file := range procFiles {
		srcPath := filepath.Join(procDir, file)
		dstPath := filepath.Join(evidencePath, file)

		if err := copyFile(srcPath, dstPath); err != nil {
			failed++
			continue
		}
		captured++
	}

	// Capture /proc/[pid]/exe symlink target
	if exePath, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		if err := os.WriteFile(filepath.Join(evidencePath, "exe"), []byte(exePath), 0600); err == nil {
			captured++
		}
	}

	// Capture /proc/[pid]/cwd symlink target
	if cwdPath, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		if err := os.WriteFile(filepath.Join(evidencePath, "cwd"), []byte(cwdPath), 0600); err == nil {
			captured++
		}
	}

	// Capture /proc/[pid]/fd/ directory (list of open file descriptors)
	fdDir := filepath.Join(procDir, "fd")
	if entries, err := os.ReadDir(fdDir); err == nil {
		var fdList strings.Builder
		for _, entry := range entries {
			link, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
			if err != nil {
				continue
			}
			fdList.WriteString(fmt.Sprintf("%s -> %s\n", entry.Name(), link))
		}
		if err := os.WriteFile(filepath.Join(evidencePath, "fd"), []byte(fdList.String()), 0600); err == nil {
			captured++
		}
	}

	// Write metadata
	meta := fmt.Sprintf("VIGIL Evidence Capture\nPID: %d\nAttack: %s\nTime: %s\nCaptured: %d files\nFailed: %d files\n",
		pid, attackType, timestamp, captured, failed)
	_ = os.WriteFile(filepath.Join(evidencePath, "META"), []byte(meta), 0600)

	if captured == 0 {
		return StatusFailed, fmt.Sprintf("pid %d: no evidence captured (process may have exited)", pid)
	}

	e.logger.Info("evidence: captured",
		zap.Uint32("pid", pid),
		zap.Int("captured", captured),
		zap.Int("failed", failed),
		zap.String("path", evidencePath),
	)
	return StatusExecuted, fmt.Sprintf("pid %d: %d files captured to %s", pid, captured, evidencePath)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}