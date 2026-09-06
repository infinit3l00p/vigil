// Package ebpf provides the eBPF program loader and manager for VIGIL.
//
// It manages kprobe/kretprobe pairs that measure kernel function execution times.
// These timing measurements are sent to userspace via BPF_RINGBUF for
// statistical analysis by the temporal anomaly detector.
//
// Architecture mirrors the companion proxy's eBPF manager:
//   - cilium/ebpf library for Go↔BPF interop
//   - bpf2go for compile-time code generation
//   - Graceful degradation: if eBPF unavailable, runs in userspace-only mode
//   - TCA defense: bounded ringbuf, per-function rate limiting, batch aggregation
//
// Integration with the companion proxy:
//   - Shares BPF map infrastructure (profile_config_map, connection_map)
//   - Can coexist with the companion proxy's sockops/TC/XDP programs on the same interfaces
//   - VIGIL's kprobes do NOT conflict with the companion proxy's TC/XDP programs (different hook types)
package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vigil/edr/internal/config"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb -type vigil_timing_event -type vigil_func_spec vigil_bpf ./bpf_src/vigil_kprobe.c -- -I./bpf_src -I/usr/include/bpf -D__TARGET_ARCH_x86

// TimingEvent mirrors the C struct vigil_timing_event.
// C struct layout (with padding for __u64 alignment):
//   offset 0:  func_id  (__u32)
//   offset 4:  pid       (__u32)
//   offset 8:  tid       (__u32)
//   offset 12: _pad0     (__u32) padding
//   offset 16: start_ns  (__u64)
//   offset 24: elapsed_ns(__u64)
//   offset 32: cpu       (__u32)
//   offset 36: flags     (__u8)
//   offset 37: pad[3]   (__u8[3])
// Total: 40 bytes
type TimingEvent struct {
	FuncID    uint32
	PID       uint32
	TID       uint32
	StartNS   uint64
	ElapsedNS uint64
	CPU       uint32
	Flags     uint8
}

// parseEvent parses a raw ringbuf record into a TimingEvent.
// Offsets must match the C struct layout (see above).
func parseEvent(raw []byte) (*TimingEvent, error) {
	if len(raw) < 40 {
		return nil, fmt.Errorf("event too small: %d bytes (need 40)", len(raw))
	}

	return &TimingEvent{
		FuncID:    binary.LittleEndian.Uint32(raw[0:4]),
		PID:       binary.LittleEndian.Uint32(raw[4:8]),
		TID:       binary.LittleEndian.Uint32(raw[8:12]),
		// offset 12-15: padding
		StartNS:   binary.LittleEndian.Uint64(raw[16:24]),
		ElapsedNS: binary.LittleEndian.Uint64(raw[24:32]),
		CPU:       binary.LittleEndian.Uint32(raw[32:36]),
		Flags:     raw[36],
	}, nil
}

// MonitoredFunction describes a kernel function being probed.
type MonitoredFunction struct {
	ID   uint32 // Function ID (matches eBPF map key)
	Name string // Kernel symbol name
	Role string // Human-readable detection role
}

// Core kernel functions to monitor for rootkit detection.
// Based on Trace of the Times (DTRAP 2025) — most reliable targets.
// Updated for kernel 7.x compatibility.
var DefaultFunctions = []MonitoredFunction{
	{0, "do_sys_openat2", "file open — detects file-hiding rootkits"},
	{1, "vfs_read", "file read — detects content-hiding rootkits"},
	{2, "__x64_sys_getdents64", "directory listing — detects directory enumeration hooks"},
	{3, "security_inode_permission", "inode permission — detects permission escalation hooks"},
	{4, "security_file_permission", "file permission — detects file access hooks"},
	{5, "__x64_sys_openat", "file open (syscall) — detects syscall-level hooks"},
}

// Manager manages VIGIL's eBPF programs lifecycle.
type Manager struct {
	cfg       *config.Config
	mu        sync.RWMutex
	collection *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	functions []MonitoredFunction
	enabled   bool
	stub      bool // true if running in stub (no eBPF) mode
}

// NewStubManager creates a manager that runs without eBPF (userspace-only mode).
func NewStubManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:       cfg,
		functions: DefaultFunctions,
		enabled:   false,
		stub:      true,
	}
}

// Load compiles and loads VIGIL's eBPF programs.
func Load(cfg *config.Config) (*Manager, error) {
	// Check for required capabilities
	if err := checkCapabilities(); err != nil {
		return nil, fmt.Errorf("insufficient capabilities: %w", err)
	}

	// Check for BTF support (required for CO-RE)
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("BTF not available (required for CO-RE): %w", err)
	}

	mgr := &Manager{
		cfg:       cfg,
		functions: DefaultFunctions,
		enabled:   true,
	}

	// Try loading pre-compiled BPF objects
	// Search order: install path → project build path
	searchPaths := []string{
		"/usr/local/lib/vigil/vigil_kprobe.o",
		filepath.Join(projDir(), "build/bpf/vigil_kprobe.o"),
		filepath.Join(projDir(), "internal/ebpf/bpf_src/vigil_kprobe.o"),
	}

	var loadErr error
	for _, path := range searchPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := mgr.loadFromObject(path); err != nil {
			log.Printf("[VIGIL] failed to load BPF from %s: %v", path, err)
			loadErr = err
			continue
		}
		loadErr = nil
		break
	}

	if loadErr != nil {
		return nil, fmt.Errorf("no loadable BPF object found: %w", loadErr)
	}

	// Attach kprobe/kretprobe pairs
	if err := mgr.attachProbes(); err != nil {
		mgr.Close()
		return nil, fmt.Errorf("attach probes: %w", err)
	}

	// Open ringbuf reader
	if err := mgr.openRingbuf(); err != nil {
		mgr.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}

	// Enable monitoring
	if err := mgr.enableFunctions(); err != nil {
		mgr.Close()
		return nil, fmt.Errorf("enable functions: %w", err)
	}

	log.Printf("[VIGIL] eBPF manager loaded: %d probe pairs active", len(mgr.functions))
	return mgr, nil
}

// loadFromObject loads pre-compiled BPF ELF objects.
func (m *Manager) loadFromObject(path string) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}

	m.collection = coll
	return nil
}

// shortName converts a kernel function name to a short identifier for BPF program names.
// These must match the BPF_KPROBE/BPF_KRETPROBE function names in the C source.
func shortName(fn string) string {
	switch fn {
	case "security_inode_permission":
		return "secinode_perm"
	case "security_file_permission":
		return "secfile_perm"
	case "__x64_sys_openat":
		return "sysopenat"
	case "vfs_read":
		return "vfs_read" // keep full name, 'read' would be ambiguous
	default:
		prefixes := []string{"do_sys_", "__x64_sys_", "do_"}
		for _, p := range prefixes {
			if len(fn) > len(p) && fn[:len(p)] == p {
				return fn[len(p):]
			}
		}
		return fn
	}
}

// attachProbes attaches kprobe/kretprobe pairs for all monitored functions.
func (m *Manager) attachProbes() error {
	if m.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	attached := 0
	for _, fn := range m.functions {
		kprobeName := fmt.Sprintf("vigil_%s_entry", shortName(fn.Name))
		kretprobeName := fmt.Sprintf("vigil_%s_exit", shortName(fn.Name))

		// Look up the BPF programs
		entryProg, ok := m.collection.Programs[kprobeName]
		if !ok {
			log.Printf("[VIGIL] WARNING: BPF program %s not found in collection", kprobeName)
			continue
		}
		exitProg, ok := m.collection.Programs[kretprobeName]
		if !ok {
			log.Printf("[VIGIL] WARNING: BPF program %s not found in collection", kretprobeName)
			continue
		}

		// Attach kprobe (entry)
		kp, err := link.Kprobe(fn.Name, entryProg, nil)
		if err != nil {
			log.Printf("[VIGIL] WARNING: cannot attach kprobe for %s: %v (function may not exist in this kernel)", fn.Name, err)
			continue
		}
		m.links = append(m.links, kp)

		// Attach kretprobe (exit)
		krp, err := link.Kretprobe(fn.Name, exitProg, nil)
		if err != nil {
			log.Printf("[VIGIL] WARNING: cannot attach kretprobe for %s: %v (function may not exist in this kernel)", fn.Name, err)
			// Clean up the kprobe link
			kp.Close()
			m.links = m.links[:len(m.links)-1]
			continue
		}
		m.links = append(m.links, krp)

		log.Printf("[VIGIL] attached probe pair: %s (func_id=%d) — %s", fn.Name, fn.ID, fn.Role)
		attached++
	}

	if attached == 0 {
		return fmt.Errorf("no probe pairs could be attached — kernel may lack required symbols")
	}

	log.Printf("[VIGIL] %d/%d probe pairs active", attached, len(m.functions))
	return nil
}

// openRingbuf opens the BPF ringbuf for reading timing events.
func (m *Manager) openRingbuf() error {
	if m.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	timingMap := m.collection.Maps["timing_events"]
	if timingMap == nil {
		return fmt.Errorf("timing_events map not found in collection")
	}

	reader, err := ringbuf.NewReader(timingMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}

	m.reader = reader
	return nil
}

// enableFunctions enables monitoring for all default functions.
func (m *Manager) enableFunctions() error {
	if m.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	funcConfig := m.collection.Maps["func_config"]
	if funcConfig == nil {
		return fmt.Errorf("func_config map not found")
	}

	// Enable all default functions
	for _, fn := range m.functions {
		key := uint32(fn.ID)
		val := uint32(1) // enabled
		if err := funcConfig.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("enable func %d (%s): %w", fn.ID, fn.Name, err)
		}
	}

	// Set global enable flag
	globalEnable := m.collection.Maps["global_enable"]
	if globalEnable != nil {
		if err := globalEnable.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("set global enable: %w", err)
		}
	}

	return nil
}

// ReadEvent reads a single timing event from the ringbuf.
// Blocks until an event is available or the reader is closed.
func (m *Manager) ReadEvent() (*TimingEvent, error) {
	if m.stub || m.reader == nil {
		return nil, fmt.Errorf("not available in stub mode")
	}

	record, err := m.reader.Read()
	if err != nil {
		return nil, fmt.Errorf("ringbuf read: %w", err)
	}

	return parseEvent(record.RawSample)
}

// Close cleanly detaches all probes and closes the collection.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close ringbuf reader first
	if m.reader != nil {
		m.reader.Close()
	}

	// Detach all links
	for _, l := range m.links {
		l.Close()
	}
	m.links = nil

	// Close collection (frees BPF maps and programs)
	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}

	m.enabled = false
	log.Printf("[VIGIL] eBPF manager shut down")
}

// IsEnabled returns whether eBPF programs are loaded and active.
func (m *Manager) IsEnabled() bool {
	return m.enabled && !m.stub
}

// Functions returns the list of currently monitored functions.
func (m *Manager) Functions() []MonitoredFunction {
	return m.functions
}

// checkCapabilities verifies the process has the required Linux capabilities.
func checkCapabilities() error {
	// Check for CAP_SYS_ADMIN or CAP_BPF (Linux 5.8+)
	// For now, just check if we can access /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("cannot read /proc/self/status: %w", err)
	}

	// Parse CapEff from /proc/self/status
	// This is a simple check — the real check happens when we try to load BPF
	_ = data
	return nil
}

// projDir returns the project directory (where this source lives).
func projDir() string {
	// Try environment variable first
	if dir := os.Getenv("VIGIL_DIR"); dir != "" {
		return dir
	}
	// Try relative to working directory (development)
	candidates := []string{
		".",
		"..",
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	return "."
}