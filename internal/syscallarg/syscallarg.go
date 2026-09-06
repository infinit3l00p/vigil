// Package syscallarg implements VIGIL's syscall argument filtering engine.
//
// Based on: eBPF-PATROL (arXiv 2511.18155) — context-aware syscall filtering.
//
// Unlike seccomp (which only filters syscall numbers), this module captures
// full syscall arguments: file paths, open flags, capability numbers, network
// endpoints, and executable paths. Combined with a rule engine, this enables:
//   - Path-based filtering: allow open("/tmp/log") but alert on open("/etc/shadow")
//   - Capability monitoring: alert on CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE
//   - Execution tracking: detect unexpected binary execution
//   - Network monitoring: detect C2 callbacks and unexpected connections
//
// Architecture (eBPF-PATROL 4-component pattern):
//   1. Probe Manager: eBPF kprobes capture syscall arguments
//   2. Rule Engine: TOML-defined rules for allow/deny/alert
//   3. Context Analyzer: process context enrichment (pid→comm→exe→uid)
//   4. Response Handler: integrated with VIGIL alert system
package syscallarg

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/config"
	"github.com/vigil/edr/internal/models"
)

// ArgEvent mirrors the C struct vigil_arg_event (304 bytes).
// C struct layout (x86-64):
//
//	offset 0:  event_type  (__u32)
//	offset 4:  pid         (__u32)
//	offset 8:  tid         (__u32)
//	offset 12: uid         (__u32)
//	offset 16: flags       (__u32)
//	offset 20: port        (__u16)
//	offset 22: _pad0       (__u16)
//	offset 24: ip_addr     (__u32)
//	offset 28: _pad1       (__u32)
//	offset 32: path        char[256]
//	offset 288: comm       char[16]
//	Total: 304 bytes
type ArgEvent struct {
	EventType uint32
	PID       uint32
	TID       uint32
	UID       uint32
	Flags     uint32
	Port      uint16
	_         uint16 // padding
	IPAddr    uint32
	_         uint32 // padding
	Path      [256]byte
	Comm      [16]byte
}

// parseArgEvent parses a raw ringbuf record into an ArgEvent.
func parseArgEvent(raw []byte) (*ArgEvent, error) {
	if len(raw) < 304 {
		return nil, fmt.Errorf("arg event too small: %d bytes (need 304)", len(raw))
	}

	var e ArgEvent
	e.EventType = binary.LittleEndian.Uint32(raw[0:4])
	e.PID = binary.LittleEndian.Uint32(raw[4:8])
	e.TID = binary.LittleEndian.Uint32(raw[8:12])
	e.UID = binary.LittleEndian.Uint32(raw[12:16])
	e.Flags = binary.LittleEndian.Uint32(raw[16:20])
	e.Port = binary.LittleEndian.Uint16(raw[20:22])
	// raw[22:24] = padding
	e.IPAddr = binary.LittleEndian.Uint32(raw[24:28])
	// raw[28:32] = padding
	copy(e.Path[:], raw[32:288])
	copy(e.Comm[:], raw[288:304])

	return &e, nil
}

// StringPath returns the path as a Go string (null-terminated).
func (e *ArgEvent) StringPath() string {
	return strings.TrimRight(string(e.Path[:]), "\x00")
}

// StringComm returns the process comm as a Go string.
func (e *ArgEvent) StringComm() string {
	return strings.TrimRight(string(e.Comm[:]), "\x00")
}

// IPString returns the IP address as a dotted-quad string.
func (e *ArgEvent) IPString() string {
	b := v4ToBytes(e.IPAddr)
	return net.IP(b[:]).String()
}

func v4ToBytes(ip uint32) [4]byte {
	return [4]byte{byte(ip), byte(ip >> 8), byte(ip >> 16), byte(ip >> 24)}
}

// CapName returns the Linux capability name for the flags field.
func (e *ArgEvent) CapName() string {
	if name, ok := models.LinuxCapabilities[e.Flags]; ok {
		return name
	}
	return fmt.Sprintf("CAP_%d", e.Flags)
}

// OpenFlagNames returns human-readable names for common open flags.
func (e *ArgEvent) OpenFlagNames() string {
	flags := e.Flags
	names := []string{}
	if flags&0x01 != 0 { // O_WRONLY
		names = append(names, "O_WRONLY")
	}
	if flags&0x02 != 0 { // O_RDWR
		names = append(names, "O_RDWR")
	}
	if flags&0x100 != 0 { // O_CREAT
		names = append(names, "O_CREAT")
	}
	if flags&0x200 != 0 { // O_TRUNC
		names = append(names, "O_TRUNC")
	}
	if flags&0x400 != 0 { // O_APPEND
		names = append(names, "O_APPEND")
	}
	if flags&0x800 != 0 { // O_DIRECTORY
		names = append(names, "O_DIRECTORY")
	}
	if flags&0x8000 != 0 { // O_DIRECT
		names = append(names, "O_DIRECT")
	}
	if len(names) == 0 {
		return "O_RDONLY"
	}
	return strings.Join(names, "|")
}

// RuleAction defines what the rule engine does when a rule matches.
type RuleAction string

const (
	ActionAllow RuleAction = "allow" // Silently allow (no alert)
	ActionAlert RuleAction = "alert" // Log alert but don't block
	ActionDeny  RuleAction = "deny"  // Alert at CRITICAL level
)

// Rule defines a syscall argument filter rule.
type Rule struct {
	ID          string     `toml:"id" json:"id"`
	Description string     `toml:"description" json:"description"`
	EventType   string     `toml:"event_type" json:"event_type"` // "open", "connect", "execve", "capable"
	PathPattern string     `toml:"path_pattern" json:"path_pattern"` // Glob pattern for path matching
	Port        uint16     `toml:"port" json:"port"`               // Network port (connect only)
	Capability  uint32     `toml:"capability" json:"capability"`   // Capability number (capable only)
	UID         uint32     `toml:"uid" json:"uid"`                  // Match specific UID (0 = any)
	Comm        string     `toml:"comm" json:"comm"`               // Match process comm name
	ExcludeComms []string  `toml:"exclude_comms" json:"exclude_comms"` // Skip alert if comm matches any
	Action      RuleAction `toml:"action" json:"action"`            // "allow", "alert", "deny"
	Severity    string     `toml:"severity" json:"severity"`        // "info", "warn", "critical"
}

// matches checks if an ArgEvent matches this rule.
func (r *Rule) matches(event *ArgEvent) bool {
	// Check event type
	if r.EventType != "" {
		typeName := models.ArgEventTypeNames[event.EventType]
		if typeName != strings.ToUpper(r.EventType) {
			return false
		}
	}

	// Check path pattern
	if r.PathPattern != "" && (event.EventType == models.ArgEventOpen || event.EventType == models.ArgEventExecve) {
		matched, _ := filepath.Match(r.PathPattern, event.StringPath())
		if !matched {
			return false
		}
	}

	// Check port (connect events)
	if r.Port != 0 && event.EventType == models.ArgEventConnect {
		if event.Port != r.Port {
			return false
		}
	}

	// Check capability (capable events)
	if r.Capability != 0 && event.EventType == models.ArgEventCapable {
		if event.Flags != r.Capability {
			return false
		}
	}

	// Check UID
	if r.UID != 0 && event.UID != r.UID {
		return false
	}

	// Check comm name
	if r.Comm != "" && event.StringComm() != r.Comm {
		return false
	}

	// Check exclude comms — skip alert if process is in the exclusion list
	// This prevents false positives from legitimate processes that use capabilities
	// frequently (e.g. ptyxis uses CAP_SYS_ADMIN for terminal operations)
	if len(r.ExcludeComms) > 0 {
		comm := event.StringComm()
		for _, ex := range r.ExcludeComms {
			if comm == ex || strings.HasPrefix(comm, ex) {
				return false // Excluded — don't alert
			}
		}
	}

	return true
}

// SyscallArgFilter is the main syscall argument filter engine.
type SyscallArgFilter struct {
	cfg    *config.Config
	alrt   *alert.AlertManager
	rules  []Rule
	mu     sync.RWMutex

	// eBPF management
	collection *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	enabled   bool
	stub      bool

	// Statistics
	stats   FilterStats
	statsMu sync.RWMutex
}

// FilterStats holds statistics about the filter engine.
type FilterStats struct {
	TotalEvents int64            `json:"total_events"`
	ByType      map[string]int64 `json:"by_type"`
	ByAction    map[string]int64 `json:"by_action"`
	RuleMatches int64            `json:"rule_matches"`
	AlertsFired int64            `json:"alerts_fired"`
}

// NewSyscallArgFilter creates a new syscall argument filter engine.
func NewSyscallArgFilter(cfg *config.Config, alrt *alert.AlertManager) *SyscallArgFilter {
	saf := &SyscallArgFilter{
		cfg:   cfg,
		alrt:  alrt,
		rules: DefaultRules(),
		stats: FilterStats{
			ByType:   make(map[string]int64),
			ByAction: make(map[string]int64),
		},
	}

	return saf
}

// DefaultRules returns the built-in default rules.
// These are conservative: alert on suspicious activity, allow normal operation.
func DefaultRules() []Rule {
	return []Rule{
		// === Allowlist rules (must come first — first match wins) ===
		{
			ID:          "allow-systemd-caps",
			Description: "Allow CAP_SYS_ADMIN for systemd",
			EventType:   "capable",
			Capability:  21,
			Comm:        "systemd",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-systemd-journal-caps",
			Description: "Allow CAP_SYS_ADMIN for systemd-journal",
			EventType:   "capable",
			Capability:  21,
			Comm:        "systemd-journal",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-systemd-uid0-caps",
			Description: "Allow capability checks by known root daemons (systemd, dbus)",
			EventType:   "capable",
			UID:         0,
			Comm:        "systemd",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-dbus-uid0-caps",
			Description: "Allow capability checks by dbus-daemon (root)",
			EventType:   "capable",
			UID:         0,
			Comm:        "dbus-daemon",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-browser-renderer-caps",
			Description: "Allow CAP_SYS_ADMIN for browser renderer sandbox (Chrome/Firefox/Electron)",
			EventType:   "capable",
			Capability:  21,
			Comm:        "Renderer",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-browser-caps",
			Description: "Allow CAP_SYS_ADMIN for browser processes (chrome, firefox, electron)",
			EventType:   "capable",
			Capability:  21,
			Comm:        "chrome",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-firefox-caps",
			Description: "Allow CAP_SYS_ADMIN for Firefox",
			EventType:   "capable",
			Capability:  21,
			Comm:        "firefox",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-electron-caps",
			Description: "Allow CAP_SYS_ADMIN for Electron apps",
			EventType:   "capable",
			Capability:  21,
			Comm:        "electron",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-systemd-resolved-caps",
			Description: "Allow CAP_NET_ADMIN for systemd-resolved",
			EventType:   "capable",
			Capability:  12,
			Comm:        "systemd-resolve",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-networkmanager-caps",
			Description: "Allow CAP_NET_ADMIN for NetworkManager",
			EventType:   "capable",
			Capability:  12,
			Comm:        "NetworkManager",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-proxy-caps",
			Description: "Allow capability checks by trusted local proxy (example rule)",
			EventType:   "capable",
			Comm:        "prx-proxy",
			Action:      ActionAllow,
		},
		{
			ID:          "allow-vigil-caps",
			Description: "Allow capability checks by VIGIL itself",
			EventType:   "capable",
			Comm:        "vigil",
			Action:      ActionAllow,
		},

		// === Path-based rules ===
		{
			ID:          "open-shadow",
			Description: "Alert on reading /etc/shadow",
			EventType:   "open",
			PathPattern: "/etc/shadow*",
			Action:      ActionAlert,
			Severity:    "warn",
		},
		{
			ID:          "open-shadow-deny",
			Description: "Critical alert on writing /etc/shadow",
			EventType:   "open",
			PathPattern: "/etc/shadow*",
			UID:         0, // root writing shadow
			Action:      ActionDeny,
			Severity:    "critical",
		},
		{
			ID:          "open-etc-passwd",
			Description: "Alert on writing /etc/passwd",
			EventType:   "open",
			PathPattern: "/etc/passwd*",
			Action:      ActionAlert,
			Severity:    "warn",
		},
		{
			ID:          "open-ssh-keys",
			Description: "Alert on accessing SSH private keys",
			EventType:   "open",
			PathPattern: "/home/*/.ssh/id_*",
			Action:      ActionAlert,
			Severity:    "warn",
		},
		{
			ID:          "open-root-ssh",
			Description: "Alert on accessing root SSH keys",
			EventType:   "open",
			PathPattern: "/root/.ssh/id_*",
			Action:      ActionDeny,
			Severity:    "critical",
		},
		{
			ID:          "open-etc-cron",
			Description: "Alert on writing cron files (possible persistence)",
			EventType:   "open",
			PathPattern: "/etc/cron*",
			Action:      ActionAlert,
			Severity:    "warn",
		},
		{
			ID:          "open-systemd-service",
			Description: "Alert on writing systemd unit files",
			EventType:   "open",
			PathPattern: "/etc/systemd/system/*",
			Action:      ActionAlert,
			Severity:    "warn",
		},

		// === Capability rules ===
		{
			ID:          "cap-sys-admin",
			Description: "Alert on CAP_SYS_ADMIN usage",
			EventType:   "capable",
			Capability:  21,
			ExcludeComms: []string{"ptyxis", "gnome-shell", "Xwayland", "systemd", "systemctl", "journalctl", "login", "sshd", "sudo", "su", "polkitd", "udisksd", "NetworkManager", "prx-proxy", "vigil", "runc", "snap-confine", "snap-update-ns", "containerd", "dockerd", "bpftool", "ss", "glxtest", "vaapitest", "forkserver", "Sandbox Forked", "localsearch-ext", "firefox", "chrome", "Renderer", "Isolate", "Sandbox", "glycin-svg", "glycin-image-rs"},
			Action:      ActionAlert,
			Severity:    "warn",
		},
		{
			ID:          "cap-net-admin",
			Description: "Alert on CAP_NET_ADMIN usage",
			EventType:   "capable",
			Capability:  12,
			ExcludeComms: []string{"systemctl", "NetworkManager", "prx-proxy", "vigil", "nft", "ss", "bpftool", "systemd-logind", "systemd-oomd", "systemd-udevd", "systemd-resolved", "snap-confine", "systemd-machine", "systemd-run", "systemd-cat", "systemd-stdio-b", "(sd-bright)", "(update-sddm-b)", "(udev-worker)", "(sh)", "wpa_supplicant", "apt-get"},
			Action:      ActionAlert,
			Severity:    "warn",
		},
		{
			ID:          "cap-sys-ptrace",
			Description: "Alert on CAP_SYS_PTRACE (debugger/process injection)",
			EventType:   "capable",
			Capability:  8,
			Action:      ActionDeny,
			Severity:    "critical",
		},
		{
			ID:          "cap-sys-rawio",
			Description: "Alert on CAP_SYS_RAWIO (direct hardware access)",
			EventType:   "capable",
			Capability:  3,
			Action:      ActionDeny,
			Severity:    "critical",
		},

		// === Execution rules ===
		{
			ID:          "exec-reverse-shell",
			Description: "Alert on common reverse shell binaries",
			EventType:   "execve",
			PathPattern: "*/ncat",
			Action:      ActionDeny,
			Severity:    "critical",
		},
		{
			ID:          "exec-shell-from-web",
			Description: "Alert on shell execution by web processes",
			EventType:   "execve",
			PathPattern: "*/bash",
			Comm:        "nginx",
			Action:      ActionDeny,
			Severity:    "critical",
		},
		{
			ID:          "exec-shell-from-web2",
			Description: "Alert on shell execution by web processes (apache)",
			EventType:   "execve",
			PathPattern: "*/sh",
			Comm:        "apache2",
			Action:      ActionDeny,
			Severity:    "critical",
		},

		// === Network rules ===
		{
			ID:          "connect-known-c2",
			Description: "Alert on connections to known C2 ports",
			EventType:   "connect",
			Port:        4444, // Metasploit default
			Action:      ActionDeny,
			Severity:    "critical",
		},
		{
			ID:          "connect-known-c2-2",
			Description: "Alert on connections to known C2 ports",
			EventType:   "connect",
			Port:        5555, // Common reverse shell port
			Action:      ActionDeny,
			Severity:    "critical",
		},
	}
}

// Load loads the syscall argument eBPF programs.
func (saf *SyscallArgFilter) Load() error {
	// Try loading pre-compiled BPF objects
	searchPaths := []string{
		"/usr/local/lib/vigil/vigil_syscall_arg.o",
		"build/bpf/vigil_syscall_arg.o",
	}

	var loadErr error
	for _, path := range searchPaths {
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			loadErr = err
			continue
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Printf("[VIGIL-SAF] failed to create collection from %s: %v", path, err)
			loadErr = err
			continue
		}

		saf.collection = coll
		loadErr = nil
		break
	}

	if loadErr != nil {
		return fmt.Errorf("no loadable syscall arg BPF object: %w", loadErr)
	}

	// Attach probes
	if err := saf.attachProbes(); err != nil {
		saf.Close()
		return fmt.Errorf("attach syscall arg probes: %w", err)
	}

	// Open ringbuf reader
	if err := saf.openRingbuf(); err != nil {
		saf.Close()
		return fmt.Errorf("open syscall arg ringbuf: %w", err)
	}

	// Enable monitoring
	if err := saf.enable(); err != nil {
		saf.Close()
		return fmt.Errorf("enable syscall arg monitoring: %w", err)
	}

	saf.enabled = true
	log.Printf("[VIGIL-SAF] syscall argument filter loaded and active")
	return nil
}

// NewStubFilter creates a filter that runs without eBPF.
func NewStubFilter(cfg *config.Config, alrt *alert.AlertManager) *SyscallArgFilter {
	return &SyscallArgFilter{
		cfg:    cfg,
		alrt:   alrt,
		rules:  DefaultRules(),
		enabled: false,
		stub:   true,
		stats: FilterStats{
			ByType:   make(map[string]int64),
			ByAction: make(map[string]int64),
		},
	}
}

// attachProbes attaches the syscall argument kprobes.
func (saf *SyscallArgFilter) attachProbes() error {
	type probeDef struct {
		progName string
		fnName   string
		role     string
	}

	probes := []probeDef{
		{"vigil_arg_open_entry", "do_sys_openat2", "file open (arg capture)"},
		{"vigil_arg_openat_entry", "__x64_sys_openat", "file open syscall (arg capture)"},
		{"vigil_arg_capable_entry", "security_capable", "capability check (arg capture)"},
		{"vigil_arg_execve_entry", "do_execveat_common.isra.0", "process execution (arg capture)"},
		{"vigil_arg_connect_entry", "__x64_sys_connect", "network connection (arg capture)"},
	}

	attached := 0
	for _, p := range probes {
		prog, ok := saf.collection.Programs[p.progName]
		if !ok {
			log.Printf("[VIGIL-SAF] WARNING: BPF program %s not found in collection", p.progName)
			continue
		}

		l, err := link.Kprobe(p.fnName, prog, nil)
		if err != nil {
			log.Printf("[VIGIL-SAF] WARNING: cannot attach kprobe for %s: %v", p.fnName, err)
			continue
		}
		saf.links = append(saf.links, l)
		log.Printf("[VIGIL-SAF] attached: %s (%s)", p.fnName, p.role)
		attached++
	}

	if attached == 0 {
		return fmt.Errorf("no syscall arg probes could be attached")
	}

	log.Printf("[VIGIL-SAF] %d/%d syscall arg probes active", attached, len(probes))
	return nil
}

// openRingbuf opens the ringbuf for reading syscall arg events.
func (saf *SyscallArgFilter) openRingbuf() error {
	if saf.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	argMap := saf.collection.Maps["arg_events"]
	if argMap == nil {
		return fmt.Errorf("arg_events map not found in collection")
	}

	reader, err := ringbuf.NewReader(argMap)
	if err != nil {
		return fmt.Errorf("syscall arg ringbuf reader: %w", err)
	}

	saf.reader = reader
	return nil
}

// enable enables the global arg monitoring switch.
func (saf *SyscallArgFilter) enable() error {
	if saf.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	globalEnable := saf.collection.Maps["arg_global_enable"]
	if globalEnable != nil {
		if err := globalEnable.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("set arg global enable: %w", err)
		}
	}
	return nil
}

// Run processes syscall arg events in a loop.
func (saf *SyscallArgFilter) Run(ctx context.Context) {
	if saf.stub || saf.reader == nil {
		log.Printf("[VIGIL-SAF] running in stub mode (no eBPF)")
		<-ctx.Done()
		return
	}

	log.Printf("[VIGIL-SAF] event processing started (%d rules loaded)", len(saf.rules))

	for {
		select {
		case <-ctx.Done():
			log.Printf("[VIGIL-SAF] shutting down")
			return
		default:
		}

		record, err := saf.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		event, err := parseArgEvent(record.RawSample)
		if err != nil {
			log.Printf("[VIGIL-SAF] parse error: %v", err)
			continue
		}

		saf.processEvent(event)
	}
}

// processEvent applies rules to an event and generates alerts if needed.
func (saf *SyscallArgFilter) processEvent(event *ArgEvent) {
	saf.statsMu.Lock()
	saf.stats.TotalEvents++
	typeName := models.ArgEventTypeNames[event.EventType]
	saf.stats.ByType[typeName]++
	saf.statsMu.Unlock()

	// Apply rules (first match wins)
	saf.mu.RLock()
	defer saf.mu.RUnlock()

	matched := false
	for _, rule := range saf.rules {
		if rule.matches(event) {
			matched = true
			saf.statsMu.Lock()
			saf.stats.RuleMatches++
			saf.stats.ByAction[string(rule.Action)]++
			saf.statsMu.Unlock()

			saf.emitAlert(event, &rule)
			break
		}
	}

	// No rule matched — log at debug level for visibility
	if !matched {
		saf.alrt.Debug("SYSCALL_ARG_FILTER",
			"unmatched %s event: pid=%d uid=%d comm=%s path=%s flags=0x%x port=%d ip=%s",
			typeName, event.PID, event.UID, event.StringComm(),
			event.StringPath(), event.Flags, event.Port, event.IPString())
	}
}

// emitAlert generates an alert for a matching rule.
func (saf *SyscallArgFilter) emitAlert(event *ArgEvent, rule *Rule) {
	typeName := models.ArgEventTypeNames[event.EventType]

	var detail string
	switch event.EventType {
	case models.ArgEventOpen, models.ArgEventExecve:
		detail = fmt.Sprintf("path=%s flags=%s", event.StringPath(), event.OpenFlagNames())
	case models.ArgEventConnect:
		detail = fmt.Sprintf("dst=%s:%d", event.IPString(), event.Port)
	case models.ArgEventCapable:
		detail = fmt.Sprintf("cap=%s(%d)", event.CapName(), event.Flags)
	default:
		detail = fmt.Sprintf("flags=0x%x", event.Flags)
	}

	msg := fmt.Sprintf("[%s] rule=%q: pid=%d uid=%d comm=%s %s",
		typeName, rule.ID, event.PID, event.UID, event.StringComm(), detail)

	switch rule.Action {
	case ActionDeny:
		saf.statsMu.Lock()
		saf.stats.AlertsFired++
		saf.statsMu.Unlock()
		saf.alrt.CriticalPID(event.PID, string(models.CatSyscallArgFilter), "%s", msg)
	case ActionAlert:
		saf.statsMu.Lock()
		saf.stats.AlertsFired++
		saf.statsMu.Unlock()
		saf.alrt.WarnPID(event.PID, string(models.CatSyscallArgFilter), "%s", msg)
	case ActionAllow:
		// Silently allow — no alert
	}
}

// Close cleans up eBPF resources.
func (saf *SyscallArgFilter) Close() {
	if saf.reader != nil {
		saf.reader.Close()
	}
	for _, l := range saf.links {
		l.Close()
	}
	if saf.collection != nil {
		saf.collection.Close()
	}
	saf.enabled = false
	log.Printf("[VIGIL-SAF] syscall argument filter shut down")
}

// IsEnabled returns whether eBPF programs are loaded and active.
func (saf *SyscallArgFilter) IsEnabled() bool {
	return saf.enabled && !saf.stub
}

// GetStats returns current filter statistics.
func (saf *SyscallArgFilter) GetStats() FilterStats {
	saf.statsMu.RLock()
	defer saf.statsMu.RUnlock()

	// Deep copy maps
	byType := make(map[string]int64, len(saf.stats.ByType))
	for k, v := range saf.stats.ByType {
		byType[k] = v
	}
	byAction := make(map[string]int64, len(saf.stats.ByAction))
	for k, v := range saf.stats.ByAction {
		byAction[k] = v
	}

	return FilterStats{
		TotalEvents: saf.stats.TotalEvents,
		ByType:      byType,
		ByAction:    byAction,
		RuleMatches: saf.stats.RuleMatches,
		AlertsFired: saf.stats.AlertsFired,
	}
}

// GetRules returns the current rule set.
func (saf *SyscallArgFilter) GetRules() []Rule {
	saf.mu.RLock()
	defer saf.mu.RUnlock()
	result := make([]Rule, len(saf.rules))
	copy(result, saf.rules)
	return result
}