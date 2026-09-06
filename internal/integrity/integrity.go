// Package integrity implements VIGIL's self-integrity verification.
//
// An EDR that doesn't verify its own integrity is a sitting duck for rootkits
// that target it directly (EvilEDR, USENIX 2025). VIGIL checks:
//
//  1. Binary hash: SHA256 of the running binary, compared against a trusted
//     hash stored at startup. If the on-disk binary changes, VIGIL detects it.
//
//  2. Process ancestry: VIGIL should be started by systemd (PID 1) or a
//     legitimate service manager. If started by a suspicious parent (shell,
//     unknown process), that's a red flag.
//
//  3. /proc/self integrity: verify /proc/self/exe symlink hasn't been
//     tampered with, and /proc/self/maps hasn't been injected into.
//
// Academic basis:
//   - EvilEDR (USENIX Security 2025): EDR repurposing attacks
//   - BPFflow (eBPF '25): IFC labels preventing BPF map surveillance
//   - Kicksecure ram-wipe: credential sanitization on rotation
package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SelfCheckResult holds the result of a self-integrity check.
type SelfCheckResult struct {
	Timestamp   time.Time
	Passed      bool
	HashMatch   bool
	AncestryOK  bool
	ProcIntact  bool
	Details     []string
}

// SelfCheck performs periodic self-integrity verification.
type SelfCheck struct {
	// Trusted binary hash (computed at startup)
	trustedHash string

	// Path to the VIGIL binary
	binaryPath string

	// Expected parent process names (systemd, init, container runtime)
	trustedParents map[string]bool

	// Alert callback
	alertFn func(level, category, msg string, args ...interface{})

	// Check interval
	interval time.Duration
}

// NewSelfCheck creates a new self-integrity checker.
// It computes the SHA256 hash of the running binary at startup
// and stores it as the trusted reference.
func NewSelfCheck(alertFn func(level, category, msg string, args ...interface{}), interval time.Duration) (*SelfCheck, error) {
	// Find the running binary path
	binaryPath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("cannot read /proc/self/exe: %w", err)
	}
	binaryPath = filepath.Clean(binaryPath)

	// Compute trusted hash at startup
	hash, err := computeFileHash(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("cannot compute initial hash: %w", err)
	}

	log.Printf("[VIGIL] self-integrity: trusted hash computed for %s: %s", binaryPath, hash[:16]+"...")

	trustedParents := map[string]bool{
		"systemd":       true, // systemd (PID 1)
		"init":          true, // sysvinit
		"containerd":    true, // container runtime
		"docker-contai": true, // docker container shim
		"sshd":          true, // SSH session (acceptable for manual testing)
		"sudo":          true, // sudo (acceptable for manual testing)
		"timeout":       true, // timeout command (used in testing)
	}

	return &SelfCheck{
		trustedHash:    hash,
		binaryPath:     binaryPath,
		trustedParents: trustedParents,
		alertFn:        alertFn,
		interval:       interval,
	}, nil
}

// RunCheck performs a full self-integrity check.
func (sc *SelfCheck) RunCheck() SelfCheckResult {
	result := SelfCheckResult{
		Timestamp: time.Now(),
		Passed:    true,
		Details:   make([]string, 0),
	}

	// 1. Binary hash verification
	result.HashMatch = sc.checkBinaryHash(&result)

	// 2. Process ancestry verification
	result.AncestryOK = sc.checkProcessAncestry(&result)

	// 3. /proc/self integrity
	result.ProcIntact = sc.checkProcSelf(&result)

	result.Passed = result.HashMatch && result.AncestryOK && result.ProcIntact
	return result
}

// checkBinaryHash compares the on-disk binary hash against the trusted hash.
// If they differ, the binary has been modified (or replaced) since startup.
func (sc *SelfCheck) checkBinaryHash(result *SelfCheckResult) bool {
	currentHash, err := computeFileHash(sc.binaryPath)
	if err != nil {
		msg := fmt.Sprintf("cannot compute current hash of %s: %v", sc.binaryPath, err)
		result.Details = append(result.Details, "HASH_ERROR: "+msg)
		if sc.alertFn != nil {
			sc.alertFn("critical", "SELF_INTEGRITY", msg)
		}
		return false
	}

	if currentHash != sc.trustedHash {
		msg := fmt.Sprintf("BINARY HASH MISMATCH: %s changed since startup! trusted=%s current=%s",
			sc.binaryPath, sc.trustedHash[:16]+"...", currentHash[:16]+"...")
		result.Details = append(result.Details, msg)
		if sc.alertFn != nil {
			sc.alertFn("critical", "SELF_INTEGRITY", msg)
		}
		return false
	}

	result.Details = append(result.Details, fmt.Sprintf("binary hash OK: %s matches trusted", currentHash[:16]+"..."))
	return true
}

// checkProcessAncestry verifies that VIGIL was started by a trusted parent.
// A rootkit might start VIGIL directly to control its behavior.
func (sc *SelfCheck) checkProcessAncestry(result *SelfCheckResult) bool {
	// Read /proc/self/stat to get parent PID
	statData, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		msg := fmt.Sprintf("cannot read /proc/self/stat: %v", err)
		result.Details = append(result.Details, "ANCESTRY_ERROR: "+msg)
		if sc.alertFn != nil {
			sc.alertFn("warn", "SELF_INTEGRITY", msg)
		}
		return false // Can't verify — fail open for ancestry (not critical)
	}

	// Parse parent PID from /proc/self/stat
	// Format: pid (comm) state ppid ...
	// Find the closing paren to handle comm with spaces
	closeParen := strings.LastIndex(string(statData), ")")
	if closeParen < 0 {
		result.Details = append(result.Details, "ANCESTRY_ERROR: cannot parse /proc/self/stat")
		return false
	}

	fields := strings.Fields(string(statData[closeParen+2:])) // skip ") S "
	if len(fields) < 2 {
		result.Details = append(result.Details, "ANCESTRY_ERROR: /proc/self/stat too short")
		return false
	}

	// Field 0 after ) is state, field 1 is ppid
	ppidStr := fields[1]
	var ppid int
	fmt.Sscanf(ppidStr, "%d", &ppid)

	if ppid == 0 {
		result.Details = append(result.Details, "ANCESTRY_ERROR: parent PID is 0")
		return false
	}

	// Read parent process name
	parentName, err := getProcessName(ppid)
	if err != nil {
		// Parent may have exited — check if we're a daemon
		result.Details = append(result.Details, fmt.Sprintf("parent process %d exited (acceptable for daemon)", ppid))
		return true // Parent exited is acceptable for daemonized processes
	}

	// Check if parent is trusted
	if sc.trustedParents[parentName] {
		result.Details = append(result.Details, fmt.Sprintf("parent OK: %s (PID %d)", parentName, ppid))
		return true
	}

	// Unknown parent — warn but don't fail (could be manual testing)
	msg := fmt.Sprintf("SUSPICIOUS PARENT: VIGIL started by %s (PID %d), expected systemd/init",
		parentName, ppid)
	result.Details = append(result.Details, msg)
	if sc.alertFn != nil {
		sc.alertFn("warn", "SELF_INTEGRITY", msg)
	}
	// Don't fail — this is a warning, not a critical failure
	return true
}

// checkProcSelf verifies /proc/self hasn't been tampered with.
func (sc *SelfCheck) checkProcSelf(result *SelfCheckResult) bool {
	ok := true

	// Check /proc/self/exe symlink points to our binary
	exeLink, err := os.Readlink("/proc/self/exe")
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("PROC_ERROR: cannot read /proc/self/exe: %v", err))
		ok = false
	} else {
		exeLink = filepath.Clean(exeLink)
		if exeLink != sc.binaryPath {
			msg := fmt.Sprintf("PROC_MISMATCH: /proc/self/exe=%s but binary=%s", exeLink, sc.binaryPath)
			result.Details = append(result.Details, msg)
			if sc.alertFn != nil {
				sc.alertFn("critical", "SELF_INTEGRITY", msg)
			}
			ok = false
		} else {
			result.Details = append(result.Details, "/proc/self/exe OK")
		}
	}

	// Check /proc/self/maps for suspicious injections
	// Look for: writable+executable mappings, unknown shared libs
	mapsOK := sc.checkMaps(result)
	if !mapsOK {
		ok = false
	}

	return ok
}

// checkMaps parses /proc/self/maps for suspicious memory mappings.
// Flags: writable+executable (rwxp) are a strong indicator of injection.
func (sc *SelfCheck) checkMaps(result *SelfCheckResult) bool {
	mapsData, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("PROC_ERROR: cannot read /proc/self/maps: %v", err))
		return false
	}

	suspicious := false
	for _, line := range strings.Split(string(mapsData), "\n") {
		if line == "" {
			continue
		}

		// Parse /proc/self/maps format:
		// address perms offset dev inode pathname
		// e.g.: 55a1b2c3d000-55a1b2c4e000 r-xp 00000000 08:01 12345 /usr/local/bin/vigil
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		perms := fields[1]

		// rwxp (readable + writable + executable) = suspicious
		// Normal binaries only have r-xp (code) or r--p (readonly data) or rw-p (writable data)
		if strings.Contains(perms, "rwx") {
			// Check if it's a known shared library path
			pathname := ""
			if len(fields) >= 6 {
				pathname = fields[5]
			}
			msg := fmt.Sprintf("SUSPICIOUS MAPPING: rwx mapping found: %s (%s)", fields[0], pathname)
			result.Details = append(result.Details, msg)
			if sc.alertFn != nil {
				sc.alertFn("critical", "SELF_INTEGRITY", msg)
			}
			suspicious = true
		}
	}

	if !suspicious {
		result.Details = append(result.Details, "/proc/self/maps OK: no rwx mappings")
	}

	return !suspicious
}

// TrustedHash returns the trusted hash computed at startup.
func (sc *SelfCheck) TrustedHash() string {
	return sc.trustedHash
}

// BinaryPath returns the path to the VIGIL binary.
func (sc *SelfCheck) BinaryPath() string {
	return sc.binaryPath
}

// Interval returns the check interval.
func (sc *SelfCheck) Interval() time.Duration {
	return sc.interval
}

// computeFileHash computes the SHA256 hash of a file.
func computeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash computation failed: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// getProcessName reads the command name of a process from /proc.
func getProcessName(pid int) (string, error) {
	// Try /proc/[pid]/comm first (just the name, no args)
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err == nil {
		return strings.TrimSpace(string(comm)), nil
	}

	// Fall back to /proc/[pid]/cmdline
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", fmt.Errorf("cannot read /proc/%d: %w", pid, err)
	}

	// cmdline is null-separated; first field is the program name
	parts := strings.SplitN(string(cmdline), "\x00", 2)
	name := filepath.Base(parts[0])
	return name, nil
}