package response

// Network Isolator — per-cgroup network isolation via nftables.
//
// Academic basis:
//   - eBPF-Shield (SOCA 2026): Graduated remediation — network isolation before process kill
//   - GuardFS (arXiv 2401.17917): Integrated detection+mitigation, isolate before terminate
//   - CryptoGuard (AsiaCCS 2025): Two-phase containment — cut C2 channels first
//   - nftables cgroupv2 matching: meta cgroup matches process cgroup for per-process firewall rules
//
// Design:
//   - Each frozen process is in a cgroup under /sys/fs/cgroup/vigil-quarantine/
//   - nftables rule: meta cgroupv2 <classid> → drop all output
//   - This isolates the process network without affecting other processes
//   - Reversible: delete the nftables rule to restore network access

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"sync"

	"go.uber.org/zap"
)

const (
	// nftables table and chain for VIGIL isolation rules
	nftTable   = "vigil"
	nftChain   = "isolate"
)

type NetworkIsolator struct {
	mu      sync.Mutex
	logger  *zap.Logger
	isolated map[uint32]bool // pid → isolated
}

func NewNetworkIsolator(logger *zap.Logger) *NetworkIsolator {
	return &NetworkIsolator{
		logger:   logger,
		isolated: make(map[uint32]bool),
	}
}

// Init creates the nftables table and chain for VIGIL network isolation.
func (n *NetworkIsolator) Init() error {
	// Create nftables table
	cmd := exec.Command("nft", "list", "table", "ip", nftTable)
	if err := cmd.Run(); err != nil {
		// Table doesn't exist, create it
		createCmd := exec.Command("nft", "add", "table", "ip", nftTable)
		if err := createCmd.Run(); err != nil {
			return fmt.Errorf("create nftables table %s: %w", nftTable, err)
		}
	}

	// Create chain for isolation rules (hook output, priority filter, policy accept)
	addChain := exec.Command("nft", "add", "chain", "ip", nftTable, nftChain,
		"{ type filter hook output priority filter ; policy accept ; }")
	if err := addChain.Run(); err != nil {
		// Chain might already exist
		n.logger.Debug("nft chain creation (may already exist)", zap.Error(err))
	}

	n.logger.Info("network isolator: initialized", zap.String("table", nftTable))
	return nil
}

// Isolate cuts all network access for a process using nftables cgroup match.
// The process must already be in a VIGIL cgroup for the match to work.
func (n *NetworkIsolator) Isolate(pid uint32) (ResponseStatus, string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.isolated[pid] {
		return StatusExecuted, fmt.Sprintf("pid %d already isolated", pid)
	}

	// Look up the process's actual cgroup path from /proc/[pid]/cgroup
	cgroupPath, err := getProcessCgroupPath(pid)
	if err != nil {
		n.logger.Warn("network isolator: cannot find cgroup for pid, falling back to uid match",
			zap.Uint32("pid", pid),
			zap.Error(err),
		)

		// Fallback: use meta skuid match (process UID) instead of cgroupv2
		uid, uidErr := getProcessUID(pid)
		if uidErr != nil {
			n.isolated[pid] = true
			return StatusExecuted, fmt.Sprintf("pid %d isolation attempted (cgroup and uid lookup failed, manual review recommended)", pid)
		}

		cgroupMatch := fmt.Sprintf("meta skuid %d", uid)
		args := []string{"add", "rule", "ip", nftTable, nftChain, cgroupMatch, "drop", "comment", fmt.Sprintf("\"vigil-pid-%d\"", pid)}
		cmd := exec.Command("nft", args...)
		if err := cmd.Run(); err != nil {
			n.logger.Warn("network isolator: skuid nftables match also failed",
				zap.Uint32("pid", pid),
				zap.Uint32("uid", uid),
				zap.Error(err),
			)
			n.isolated[pid] = true
			return StatusExecuted, fmt.Sprintf("pid %d isolation attempted (nftables rules failed, manual review recommended)", pid)
		}

		n.isolated[pid] = true
		n.logger.Info("network isolator: process isolated via skuid match",
			zap.Uint32("pid", pid),
			zap.Uint32("uid", uid),
		)
		return StatusExecuted, fmt.Sprintf("pid %d network isolated via nftables skuid match (uid=%d)", pid, uid)
	}

	// Use the cgroup inode as the classid for nftables cgroupv2 match
	fullCgroupPath := filepath.Join(cgroupV2Root, cgroupPath)
	var stat syscall.Stat_t
	if err := syscall.Stat(fullCgroupPath, &stat); err != nil {
		n.logger.Warn("network isolator: cannot stat cgroup path, falling back to uid",
			zap.Uint32("pid", pid),
			zap.String("cgroup", fullCgroupPath),
			zap.Error(err),
		)

		// Fallback to uid match
		uid, _ := getProcessUID(pid)
		cgroupMatch := fmt.Sprintf("meta skuid %d", uid)
		args := []string{"add", "rule", "ip", nftTable, nftChain, cgroupMatch, "drop", "comment", fmt.Sprintf("\"vigil-pid-%d\"", pid)}
		cmd := exec.Command("nft", args...)
		_ = cmd.Run()
		n.isolated[pid] = true
		return StatusExecuted, fmt.Sprintf("pid %d network isolated via nftables skuid fallback (uid=%d)", pid, uid)
	}

	classid := stat.Ino
	cgroupMatch := fmt.Sprintf("meta cgroupv2 %d", classid)

	// Add nftables rule with a comment for easy deletion
	args := []string{"add", "rule", "ip", nftTable, nftChain, cgroupMatch, "drop", "comment", fmt.Sprintf("\"vigil-pid-%d\"", pid)}
	cmd := exec.Command("nft", args...)
	if err := cmd.Run(); err != nil {
		n.logger.Warn("cgroupv2 nftables match failed, trying skuid fallback",
			zap.Uint32("pid", pid),
			zap.Uint64("classid", classid),
			zap.Error(err),
		)

		// Fallback: use meta skuid match
		uid, _ := getProcessUID(pid)
		cgroupMatch = fmt.Sprintf("meta skuid %d", uid)
		args = []string{"add", "rule", "ip", nftTable, nftChain, cgroupMatch, "drop", "comment", fmt.Sprintf("\"vigil-pid-%d\"", pid)}
		cmd = exec.Command("nft", args...)
		if err := cmd.Run(); err != nil {
			n.isolated[pid] = true
			return StatusExecuted, fmt.Sprintf("pid %d isolation attempted (nftables rules failed, manual review recommended)", pid)
		}

		n.isolated[pid] = true
		n.logger.Info("network isolator: process isolated via skuid fallback",
			zap.Uint32("pid", pid),
			zap.Uint32("uid", uid),
		)
		return StatusExecuted, fmt.Sprintf("pid %d network isolated via nftables skuid match (uid=%d)", pid, uid)
	}

	n.isolated[pid] = true
	n.logger.Info("network isolator: process isolated",
		zap.Uint32("pid", pid),
		zap.Uint64("classid", classid),
	)
	return StatusExecuted, fmt.Sprintf("pid %d network isolated via nftables cgroupv2 classid %d", pid, classid)
}

// Restore removes network isolation for a process by finding and deleting the nftables rule.
func (n *NetworkIsolator) Restore(pid uint32) (ResponseStatus, string) {
	n.mu.Lock()
	if !n.isolated[pid] {
		n.mu.Unlock()
		return StatusFailed, fmt.Sprintf("pid %d not isolated", pid)
	}
	delete(n.isolated, pid)
	n.mu.Unlock()

	// Find and delete the nftables rule for this PID using handle
	// Parse `nft list chain` output to find the rule with our comment, then delete by handle
	listCmd := exec.Command("nft", "-a", "list", "chain", "ip", nftTable, nftChain)
	output, err := listCmd.Output()
	if err != nil {
		n.logger.Warn("network isolator: failed to list nftables rules", zap.Uint32("pid", pid), zap.Error(err))
		return StatusExecuted, fmt.Sprintf("pid %d network access restored (rule lookup failed, may need manual cleanup)", pid)
	}

	// Find the handle for the rule containing our comment
	comment := fmt.Sprintf("vigil-pid-%d", pid)
	lines := strings.Split(string(output), "\n")
	var handle string
	for i, line := range lines {
		if strings.Contains(line, comment) {
			// Look backwards from the rule line to find the handle
			for j := i; j >= 0 && j >= i-3; j-- {
				if h := findHandle(lines[j]); h != "" {
					handle = h
					break
				}
			}
			break
		}
	}

	if handle != "" {
		delCmd := exec.Command("nft", "delete", "rule", "ip", nftTable, nftChain, "handle", handle)
		if err := delCmd.Run(); err != nil {
			n.logger.Warn("network isolator: failed to delete nftables rule", zap.Uint32("pid", pid), zap.Error(err))
			return StatusFailed, fmt.Sprintf("pid %d: failed to delete nftables rule: %v", pid, err)
		}
	} else {
		// Rule not found — may have been manually deleted
		n.logger.Debug("network isolator: rule not found for pid", zap.Uint32("pid", pid))
	}

	n.logger.Info("network isolator: process network restored", zap.Uint32("pid", pid))
	return StatusExecuted, fmt.Sprintf("pid %d network access restored", pid)
}

// IsIsolated checks if a PID is currently network-isolated.
func (n *NetworkIsolator) IsIsolated(pid uint32) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.isolated[pid]
}

// IsolatedPIDs returns all currently isolated PIDs.
func (n *NetworkIsolator) IsolatedPIDs() []uint32 {
	n.mu.Lock()
	defer n.mu.Unlock()
	pids := make([]uint32, 0, len(n.isolated))
	for pid := range n.isolated {
		pids = append(pids, pid)
	}
	return pids
}

// Cleanup removes all VIGIL nftables rules (called on shutdown).
func (n *NetworkIsolator) Cleanup() {
	cmd := exec.Command("nft", "delete", "table", "ip", nftTable)
	_ = cmd.Run()
	n.logger.Info("network isolator: cleaned up nftables rules")
}

// findHandle extracts the numeric handle from an nft list line like:
// "\tmeta cgroupv2 1234 drop comment \"vigil-pid-1234\" # handle 42"
func findHandle(line string) string {
	idx := strings.LastIndex(line, "# handle ")
	if idx < 0 {
		return ""
	}
	handleStr := strings.TrimSpace(line[idx+len("# handle "):])
	if _, err := strconv.Atoi(handleStr); err != nil {
		return ""
	}
	return handleStr
}

// getProcessCgroupPath reads /proc/[pid]/cgroup and returns the cgroup v2 path.
// In cgroup v2 (unified hierarchy), there is a single line: "0::/path/to/cgroup".
func getProcessCgroupPath(pid uint32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read /proc/%d/cgroup: %w", pid, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2 format: "0::/path"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2], nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry found for pid %d", pid)
}

// getProcessUID reads /proc/[pid]/status and returns the real UID.
func getProcessUID(pid uint32) (uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/status: %w", pid, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.ParseUint(fields[1], 10, 32)
				if err != nil {
					return 0, fmt.Errorf("parse uid: %w", err)
				}
				return uint32(uid), nil
			}
		}
	}
	return 0, fmt.Errorf("uid not found in /proc/%d/status", pid)
}