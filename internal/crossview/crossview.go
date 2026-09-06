// Package crossview provides cross-view integrity checking for VIGIL.
//
// Based on: Kernel-level Rootkit Detection Taxonomy (arXiv 2304.00473)
//
// Cross-view detection compares the kernel's view of the system (captured via
// eBPF tracepoints) against what userspace tools see (/proc, /proc/net/tcp, ls).
// Discrepancies indicate hidden objects — a classic rootkit technique.
//
// Three domains:
//   1. Process view: eBPF fork/exec/exit vs /proc/[pid] enumeration
//   2. Connection view: eBPF TCP state changes vs /proc/net/tcp
//   3. File view: eBPF file opens vs userspace directory listings
//
// Interceptor-aware: understands that LD_PRELOAD interceptors create
// legitimate discrepancies in /proc/self/maps and network connections.
// These are NOT flagged as rootkit activity.
package crossview

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// Cross-view event types (must match eBPF C defines)
const (
	CVEventFork      = 1
	CVEventExec      = 2
	CVEventExit      = 3
	CVEventRename    = 4
	CVEventTCPState  = 5
)

// TCP states (must match Linux defines)
const (
	TCPEstablished = 1
	TCPSynSent     = 2
	TCPSynRecv     = 3
	TCPFinWait1    = 4
	TCPFinWait2    = 5
	TCPTimeWait    = 6
	TCPClose       = 7
	TCPCloseWait   = 8
	TCPLastAck     = 9
	TCPListen      = 10
	TCPClosing     = 11
	TCPNewSynRecv  = 12
)

// TCPStateNames maps TCP state numbers to names
var TCPStateNames = map[uint32]string{
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW_SYN_RECV",
}

// CVEventTypeNames maps event type IDs to human-readable names
var CVEventTypeNames = map[uint32]string{
	CVEventFork:     "FORK",
	CVEventExec:     "EXEC",
	CVEventExit:     "EXIT",
	CVEventRename:   "RENAME",
	CVEventTCPState: "TCP_STATE",
}

// ProcessInfo represents a process tracked by eBPF
type ProcessInfo struct {
	PID     uint32
	PPID    uint32
	StartNS uint64
	ExitNS  uint64
	UID     uint32
	Comm    string
	Path    string
	Alive   bool
}

// ConnectionInfo represents a TCP connection tracked by eBPF
type ConnectionInfo struct {
	PID        uint32
	Family     uint16
	Protocol   uint16
	SrcPort    uint16
	DstPort    uint16
	SrcIP      net.IP
	DstIP      net.IP
	OldState   uint32
	NewState   uint32
	Timestamp  uint64
}

// Mismatch represents a discrepancy between kernel and userspace views
type Mismatch struct {
	Type      string    // "process", "connection", "file"
	KernelPID uint32    // PID seen by kernel (0 if only in userspace)
	UserPID    uint32    // PID seen by userspace (0 if only in kernel)
	Detail    string    // Human-readable description
	Severity  string    // "warn" or "critical"
	Timestamp time.Time
}

// Stats tracks cross-view module statistics
type Stats struct {
	KernelProcesses uint64            // processes tracked by eBPF
	KernelConns     uint64            // connections tracked by eBPF
	Mismatches      uint64            // total mismatches detected
	ProcessMismatches uint64          // process view mismatches
	ConnMismatches    uint64          // connection view mismatches
	FileMismatches    uint64          // file view mismatches
	EventsReceived    uint64          // total eBPF events received
	Reconciliations   uint64          // number of reconciliation cycles
	ByType           map[uint32]uint64 // events by type
	LastReconcile    time.Time         // last reconciliation time
}

// CrossViewChecker manages cross-view integrity checking
type CrossViewChecker struct {
	cfg       *config.Config
	alert     *alert.AlertManager
	collection *ebpf.Collection
	links     []link.Link
	reader    *ringbuf.Reader
	enabled   bool
	stub      bool

	// Kernel view (from eBPF)
	processes map[uint32]*ProcessInfo  // PID → process info
	conns     map[string]*ConnectionInfo // connKey → connection info

	// Userspace view (from /proc)
	userProcesses map[uint32]bool // PIDs seen in /proc
	userConns    map[string]bool // connections seen in /proc/net/tcp

	mu       sync.RWMutex
	statsMu  sync.RWMutex
	stats    Stats
	stopCh   chan struct{}
}

// Lock ordering convention (BUG-037):
// When acquiring both cvc.mu and cvc.statsMu, always acquire cvc.mu FIRST,
// then cvc.statsMu. Never acquire cvc.mu while holding cvc.statsMu.
// This prevents deadlock and ensures consistent lock acquisition order.
//
// reconcile() is an exception: it copies maps under cvc.mu, releases cvc.mu,
// then acquires cvc.statsMu independently for counter updates.

// ConnKey uniquely identifies a TCP connection
// Using string keys because net.IP is not comparable for maps
func connKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", srcIP.String(), srcPort, dstIP.String(), dstPort)
}

// NewCrossViewChecker creates a new cross-view integrity checker
func NewCrossViewChecker(cfg *config.Config, alrt *alert.AlertManager) *CrossViewChecker {
	return &CrossViewChecker{
		cfg:           cfg,
		alert:         alrt,
		processes:     make(map[uint32]*ProcessInfo),
		conns:         make(map[string]*ConnectionInfo),
		userProcesses: make(map[uint32]bool),
		userConns:    make(map[string]bool),
		stopCh:        make(chan struct{}),
	}
}

// NewStubChecker creates a stub checker (no eBPF)
func NewStubChecker(cfg *config.Config, alrt *alert.AlertManager) *CrossViewChecker {
	cvc := NewCrossViewChecker(cfg, alrt)
	cvc.stub = true
	cvc.enabled = false
	return cvc
}

// Load loads the cross-view eBPF programs
func (cvc *CrossViewChecker) Load() error {
	searchPaths := []string{
		"/usr/local/lib/vigil/vigil_crossview.o",
		filepath.Join(projDir(), "build/bpf/vigil_crossview.o"),
		filepath.Join(projDir(), "internal/ebpf/bpf_src/vigil_crossview.o"),
	}

	var loadErr error
	for _, path := range searchPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if err := cvc.loadFromObject(path); err != nil {
			log.Printf("[VIGIL-CV] failed to load BPF from %s: %v", path, err)
			loadErr = err
			continue
		}
		loadErr = nil
		break
	}

	if loadErr != nil {
		return fmt.Errorf("no loadable BPF object found: %w", loadErr)
	}

	// Attach tracepoints
	if err := cvc.attachTracepoints(); err != nil {
		cvc.Close()
		return fmt.Errorf("attach tracepoints: %w", err)
	}

	// Open ringbuf reader
	if err := cvc.openRingbuf(); err != nil {
		cvc.Close()
		return fmt.Errorf("open ringbuf: %w", err)
	}

	// Enable monitoring
	if err := cvc.enable(); err != nil {
		cvc.Close()
		return fmt.Errorf("enable: %w", err)
	}

	cvc.enabled = true
	log.Printf("[VIGIL-CV] cross-view integrity checker loaded")
	return nil
}

// loadFromObject loads pre-compiled BPF ELF objects
func (cvc *CrossViewChecker) loadFromObject(path string) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}

	cvc.collection = coll
	return nil
}

// attachTracepoints attaches all cross-view tracepoint programs
func (cvc *CrossViewChecker) attachTracepoints() error {
	type tpAttach struct {
		progName string
		category string
		event    string
	}

	attachments := []tpAttach{
		{"handle_sched_process_fork", "sched", "sched_process_fork"},
		{"handle_sched_process_exec", "sched", "sched_process_exec"},
		{"handle_sched_process_exit", "sched", "sched_process_exit"},
		{"handle_task_rename", "task", "task_rename"},
		{"handle_inet_sock_set_state", "sock", "inet_sock_set_state"},
	}

	attached := 0
	for _, a := range attachments {
		prog, ok := cvc.collection.Programs[a.progName]
		if !ok {
			log.Printf("[VIGIL-CV] WARNING: BPF program %s not found in collection", a.progName)
			continue
		}

		tp, err := link.Tracepoint(a.category, a.event, prog, nil)
		if err != nil {
			log.Printf("[VIGIL-CV] WARNING: cannot attach tracepoint %s/%s: %v", a.category, a.event, err)
			continue
		}
		cvc.links = append(cvc.links, tp)
		log.Printf("[VIGIL-CV] attached tracepoint: %s/%s → %s", a.category, a.event, a.progName)
		attached++
	}

	if attached == 0 {
		return fmt.Errorf("no tracepoints could be attached")
	}

	log.Printf("[VIGIL-CV] %d/%d tracepoints active", attached, len(attachments))
	return nil
}

// openRingbuf opens the BPF ringbuf for reading cross-view events
func (cvc *CrossViewChecker) openRingbuf() error {
	if cvc.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	eventsMap := cvc.collection.Maps["cv_events"]
	if eventsMap == nil {
		return fmt.Errorf("cv_events map not found in collection")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("ringbuf reader: %w", err)
	}

	cvc.reader = reader
	return nil
}

// enable enables the cross-view eBPF programs
func (cvc *CrossViewChecker) enable() error {
	if cvc.collection == nil {
		return fmt.Errorf("no collection loaded")
	}

	globalEnable := cvc.collection.Maps["cv_global_enable"]
	if globalEnable != nil {
		if err := globalEnable.Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("set global enable: %w", err)
		}
	}
	return nil
}

// Run starts the cross-view event processing loop
func (cvc *CrossViewChecker) Run(ctx context.Context) {
	if cvc.stub || !cvc.enabled {
		log.Printf("[VIGIL-CV] running in stub mode (no eBPF)")
		return
	}

	log.Printf("[VIGIL-CV] starting event loop...")

	// Start reconciliation goroutine
	go cvc.reconcileLoop(ctx)

	// Process events from ringbuf
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := cvc.reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return // context cancelled
			}
			log.Printf("[VIGIL-CV] ringbuf read error: %v", err)
			continue
		}

		cvc.processEvent(record.RawSample)
	}
}

// processEvent parses a raw ringbuf event
func (cvc *CrossViewChecker) processEvent(raw []byte) {
	if len(raw) < 4 {
		return
	}

	eventType := binary.LittleEndian.Uint32(raw[0:4])

	cvc.statsMu.Lock()
	cvc.stats.EventsReceived++
	if cvc.stats.ByType == nil {
		cvc.stats.ByType = make(map[uint32]uint64)
	}
	cvc.stats.ByType[eventType]++
	cvc.statsMu.Unlock()

	switch eventType {
	case CVEventFork:
		cvc.handleFork(raw)
	case CVEventExec:
		cvc.handleExec(raw)
	case CVEventExit:
		cvc.handleExit(raw)
	case CVEventRename:
		cvc.handleRename(raw)
	case CVEventTCPState:
		cvc.handleTCPState(raw)
	default:
		log.Printf("[VIGIL-CV] unknown event type: %d", eventType)
	}
}

// parseForkEvent parses a fork event from raw bytes
// Layout: event_type(4) + pid(4) + ppid(4) + _pad(4) + timestamp(8) + parent_comm(16) + child_comm(16) = 56 bytes
func parseForkEvent(raw []byte) (pid, ppid uint32, timestamp uint64, parentComm, childComm string) {
	if len(raw) < 56 {
		return
	}
	pid = binary.LittleEndian.Uint32(raw[4:8])
	ppid = binary.LittleEndian.Uint32(raw[8:12])
	// offset 12: 4 bytes padding
	timestamp = binary.LittleEndian.Uint64(raw[16:24])
	parentComm = strings.TrimRight(string(raw[24:40]), "\x00")
	childComm = strings.TrimRight(string(raw[40:56]), "\x00")
	return
}

// parseExecEvent parses an exec event from raw bytes
// Layout: event_type(4) + pid(4) + old_pid(4) + _pad(4) + timestamp(8) + comm(16) + path(128) = 164 bytes
func parseExecEvent(raw []byte) (pid, oldPID uint32, timestamp uint64, comm, path string) {
	if len(raw) < 160 {
		return
	}
	pid = binary.LittleEndian.Uint32(raw[4:8])
	oldPID = binary.LittleEndian.Uint32(raw[8:12])
	// offset 12: 4 bytes padding
	timestamp = binary.LittleEndian.Uint64(raw[16:24])
	comm = strings.TrimRight(string(raw[24:40]), "\x00")
	path = strings.TrimRight(string(raw[40:168]), "\x00")
	return
}

// parseExitEvent parses an exit event from raw bytes
// Layout: event_type(4) + pid(4) + group_dead(4) + _pad(4) + timestamp(8) + comm(16) = 40 bytes
func parseExitEvent(raw []byte) (pid, groupDead uint32, timestamp uint64, comm string) {
	if len(raw) < 40 {
		return
	}
	pid = binary.LittleEndian.Uint32(raw[4:8])
	groupDead = binary.LittleEndian.Uint32(raw[8:12])
	// offset 12: 4 bytes padding
	timestamp = binary.LittleEndian.Uint64(raw[16:24])
	comm = strings.TrimRight(string(raw[24:40]), "\x00")
	return
}

// parseRenameEvent parses a rename event from raw bytes
// Layout: event_type(4) + pid(4) + _pad(4) + timestamp(8) + oldcomm(16) + newcomm(16) = 52 bytes
func parseRenameEvent(raw []byte) (pid uint32, timestamp uint64, oldComm, newComm string) {
	if len(raw) < 52 {
		return
	}
	pid = binary.LittleEndian.Uint32(raw[4:8])
	// offset 8: 4 bytes padding
	timestamp = binary.LittleEndian.Uint64(raw[12:20])
	oldComm = strings.TrimRight(string(raw[20:36]), "\x00")
	newComm = strings.TrimRight(string(raw[36:52]), "\x00")
	return
}

// parseTCPEvent parses a TCP state event from raw bytes
func parseTCPEvent(raw []byte) (pid uint32, sport, dport uint16, oldState, newState uint32, timestamp uint64, srcIP, dstIP net.IP) {
	if len(raw) < 40 {
		return
	}
	pid = binary.LittleEndian.Uint32(raw[4:8])
	// family(2) at offset 8, protocol(2) at offset 10 — skip
	sport = binary.LittleEndian.Uint16(raw[12:14])
	dport = binary.LittleEndian.Uint16(raw[14:16])
	srcIP = net.IP(raw[16:20])
	dstIP = net.IP(raw[20:24])
	oldState = binary.LittleEndian.Uint32(raw[24:28])
	newState = binary.LittleEndian.Uint32(raw[28:32])
	timestamp = binary.LittleEndian.Uint64(raw[32:40])
	return
}

// handleFork processes a fork event
func (cvc *CrossViewChecker) handleFork(raw []byte) {
	pid, ppid, _, parentComm, childComm := parseForkEvent(raw)
	if pid == 0 {
		return
	}

	cvc.mu.Lock()
	cvc.processes[pid] = &ProcessInfo{
		PID:     pid,
		PPID:    ppid,
		StartNS: uint64(time.Now().UnixNano()),
		Comm:    childComm,
		Alive:   true,
	}
	cvc.mu.Unlock()

	cvc.statsMu.Lock()
	cvc.stats.KernelProcesses = uint64(len(cvc.processes))
	cvc.statsMu.Unlock()

	log.Printf("[VIGIL-CV] FORK: pid=%d ppid=%d parent=%s child=%s", pid, ppid, parentComm, childComm)
}

// handleExec processes an exec event
func (cvc *CrossViewChecker) handleExec(raw []byte) {
	pid, _, _, comm, path := parseExecEvent(raw)
	if pid == 0 {
		return
	}

	cvc.mu.Lock()
	if proc, ok := cvc.processes[pid]; ok {
		proc.Comm = comm
		proc.Path = path
	} else {
		cvc.processes[pid] = &ProcessInfo{
			PID:   pid,
			Comm:  comm,
			Path:  path,
			Alive: true,
		}
	}
	cvc.mu.Unlock()

	log.Printf("[VIGIL-CV] EXEC: pid=%d comm=%s path=%s", pid, comm, path)
}

// handleExit processes an exit event
func (cvc *CrossViewChecker) handleExit(raw []byte) {
	pid, _, _, comm := parseExitEvent(raw)
	if pid == 0 {
		return
	}

	cvc.mu.Lock()
	if proc, ok := cvc.processes[pid]; ok {
		proc.Alive = false
		proc.ExitNS = uint64(time.Now().UnixNano())
	}
	cvc.mu.Unlock()

	log.Printf("[VIGIL-CV] EXIT: pid=%d comm=%s", pid, comm)
}

// handleRename processes a rename event
func (cvc *CrossViewChecker) handleRename(raw []byte) {
	pid, _, oldComm, newComm := parseRenameEvent(raw)
	if pid == 0 {
		return
	}

	cvc.mu.Lock()
	if proc, ok := cvc.processes[pid]; ok {
		proc.Comm = newComm
	}
	cvc.mu.Unlock()

	log.Printf("[VIGIL-CV] RENAME: pid=%d %s → %s", pid, oldComm, newComm)
}

// handleTCPState processes a TCP state change event
func (cvc *CrossViewChecker) handleTCPState(raw []byte) {
	pid, sport, dport, oldState, newState, _, srcIP, dstIP := parseTCPEvent(raw)

	stateName := func(s uint32) string {
		if n, ok := TCPStateNames[s]; ok {
			return n
		}
		return fmt.Sprintf("STATE_%d", s)
	}

	// Only log important transitions
	if newState == TCPEstablished || newState == TCPListen {
		log.Printf("[VIGIL-CV] TCP: pid=%d %s:%d → %s:%d %s → %s",
			pid, srcIP, sport, dstIP, dport, stateName(oldState), stateName(newState))
	}

	cvc.mu.Lock()
	if newState == TCPEstablished || newState == TCPListen {
		// Track the connection — use a composite key from pid+sport+dport+ips
		connKey := fmt.Sprintf("%d:%d:%d:%s:%s", pid, sport, dport, srcIP.String(), dstIP.String())
		cvc.conns[connKey] = &ConnectionInfo{
			PID:       pid,
			SrcPort:   sport,
			DstPort:   dport,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			OldState:  oldState,
			NewState:  newState,
			Timestamp: 0,
		}
	} else if newState == TCPClose || newState == TCPTimeWait {
		// Remove closed connections to prevent unbounded growth (BUG-011 fix)
		connKey := fmt.Sprintf("%d:%d:%d:%s:%s", pid, sport, dport, srcIP.String(), dstIP.String())
		delete(cvc.conns, connKey)
	}
	cvc.stats.KernelConns = uint64(len(cvc.conns))
	cvc.mu.Unlock()
}

// reconcileLoop periodically compares kernel view against userspace view
func (cvc *CrossViewChecker) reconcileLoop(ctx context.Context) {
	// Initial delay to let eBPF collect some baseline data
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(60 * time.Second) // reconcile every 60 seconds
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(5 * time.Minute) // prune dead processes every 5 min
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cvc.reconcile()
		case <-cleanupTicker.C:
			cvc.pruneDeadProcesses()
		}
	}
}

// pruneDeadProcesses removes process entries that have been dead for more than 10 minutes.
// This prevents unbounded memory growth on systems with high process churn (BUG-011 fix).
func (cvc *CrossViewChecker) pruneDeadProcesses() {
	cvc.mu.Lock()
	defer cvc.mu.Unlock()

	now := time.Now().UnixNano()
	var removed int
	for pid, proc := range cvc.processes {
		if !proc.Alive {
			// If ExitNS is set and process has been dead for > 10 minutes, remove it
			if proc.ExitNS > 0 && (now-int64(proc.ExitNS)) > 10*60*1e9 {
				delete(cvc.processes, pid)
				removed++
			}
		}
	}
	if removed > 0 {
		cvc.statsMu.Lock()
		cvc.stats.KernelProcesses = uint64(len(cvc.processes))
		cvc.statsMu.Unlock()
		log.Printf("[VIGIL-CV] pruned %d dead processes", removed)
	}
}

// reconcile compares kernel eBPF view against userspace /proc view.
//
// BUG-029 fix: Copy the processes and conns maps under lock, then release
// the lock before doing filesystem I/O (os.ReadDir, os.ReadFile) and alert
// generation. This prevents holding cvc.mu during potentially slow I/O.
func (cvc *CrossViewChecker) reconcile() {
	// Snapshot kernel view under lock
	cvc.mu.Lock()
	procSnapshot := make(map[uint32]*ProcessInfo, len(cvc.processes))
	for k, v := range cvc.processes {
		cp := *v
		procSnapshot[k] = &cp
	}
	connSnapshot := make(map[string]*ConnectionInfo, len(cvc.conns))
	for k, v := range cvc.conns {
		cp := *v
		connSnapshot[k] = &cp
	}
	cvc.mu.Unlock()

	cvc.statsMu.Lock()
	cvc.stats.Reconciliations++
	cvc.stats.LastReconcile = time.Now()
	cvc.statsMu.Unlock()

	// 1. Process reconciliation: compare eBPF processes vs /proc
	cvc.reconcileProcesses(procSnapshot)

	// 2. Connection reconciliation: compare eBPF connections vs /proc/net/tcp
	cvc.reconcileConnections(connSnapshot)
}

// Known sandbox/container process name prefixes that legitimately hide from /proc.
// These are Firefox content sandbox processes, container runtimes, etc.
// They use PID namespaces that make them invisible to a simple /proc walk,
// which is normal OS behavior, NOT a rootkit hiding them.
var sandboxProcessPrefixes = []string{
	// Firefox sandbox processes
	"Web Content",          // Firefox content sandbox
	"Isolated Web Co",      // Firefox isolated web content (truncated)
	"Isolated Web Content", // Firefox isolated web content
	"Socket Thread",        // Firefox socket thread
	"MainThread",           // Firefox main thread
	"pool-spawner",         // Firefox pool spawner
	"DOM Worker",           // Firefox DOM worker
	"StyleThread",          // Firefox style thread
	"compositing",          // Firefox compositor
	"VRListener",           // Firefox VR listener
	"ImgDecoder",           // Firefox image decoder
	"DNS Resolver",         // Firefox DNS resolver
	"IPDL Background",      // Firefox IPC
	"Speech",               // Firefox speech
	"VideoDecoder",          // Firefox video decoder
	"Renderer",             // Firefox/GPU renderer sandbox
	"Cache2 I/O",           // Firefox cache I/O thread
	"FS Broker",             // Firefox file system broker
	"StyleCache",            // Firefox style cache
	"HTML Parser",           // Firefox HTML parser
	"ImageDecoder",          // Firefox image decoder (alternate name)
	"Netlink Monitor",       // Firefox network monitor
	"ProcessHangMon",       // Firefox hang monitor
	// Chromium/Chrome sandbox processes (v7.2.17 fix: was causing CROSS_VIEW false positives)
	"chrome",               // Chromium browser (all threads: renderer, GPU, utility)
	"ThreadPoolForeg",      // Chromium ThreadPoolForeground (truncated comm)
	"ThreadPoolBackg",      // Chromium ThreadPoolBackground (truncated comm)
	"Privileged Cont",      // Chromium PrivilegedProcessController (truncated)
	"CanvasRenderer",       // Chromium Canvas renderer thread
	"MediaSu~isor",          // Chromium Media supervisor (truncated comm, kernel truncates)
	"WebExtensions",        // Firefox/Chrome web extensions process
	"AudioThread",           // Chromium audio thread
	"Compositor",            // Chromium compositor thread
	"CompositorTileW",       // Chromium compositor tile worker (truncated)
	"GpuMemoryThread",      // Chromium GPU memory thread
	"VizCompositorTh",      // Chromium Viz compositor thread (truncated)
	"CrRendererMain",       // Chromium renderer main thread
	"ChromeIOThread",        // Chromium I/O thread
	"NetworkService",       // Chromium network service
	"Utility",               // Chromium utility process
	"utility",               // Chromium utility (lowercase)
	// Steam
	"steamwebhelper",       // Steam web helper (Chromium-based, uses sandbox)
	// Other sandboxed apps
	"ollama",               // Ollama LLM server (uses PID namespace for isolation)
	"ptyxis",               // Ptyxis terminal (uses CAP_SYS_ADMIN for /proc access)
	// Additional system/GNOME processes (v0.5.5: cross-view false positive fix)
	"ai-agent",              // example: local AI assistant process
		"agent-tui",           // example: its TUI frontend
	"gjs",                   // GNOME JavaScript (gnome-shell components)
	"mutter-x11-fram",       // Mutter X11 frame (GNOME compositor, truncated comm)
	"ibus-extension-",       // IBus input method extension (truncated comm)
	"blueman-applet",        // Bluetooth applet
	"snapd-desktop-i",       // Snap desktop integration (truncated comm)
	"update-notifier",      // Ubuntu update notifier
	"soffice.bin",           // LibreOffice
	"systemd-machine",      // systemd machined
	"(sd-bright)",          // systemd brightness handler
	"(update-sddm-b)",      // systemd SDDM brightness update
	"(udev-worker)",        // udev worker
	"(sh)",                 // shell subprocesses (parenthesized by kernel)
}

// isSandboxProcess checks if a process name matches known sandbox processes
// that legitimately hide from /proc enumeration.
func isSandboxProcess(comm string) bool {
	for _, prefix := range sandboxProcessPrefixes {
		if strings.HasPrefix(comm, prefix) || comm == prefix {
			return true
		}
	}
	return false
}

// reconcileProcesses compares kernel process view vs /proc
func (cvc *CrossViewChecker) reconcileProcesses(procSnapshot map[uint32]*ProcessInfo) {
	// Enumerate /proc for userspace view
	userPIDs := cvc.enumerateProc()

	// Find processes in kernel view but NOT in userspace (hidden by rootkit)
	kernelOnly := 0
	for pid, proc := range procSnapshot {
		if !proc.Alive {
			continue // Skip dead processes
		}
		if !userPIDs[pid] {
			// Process visible to kernel but NOT visible in /proc
			// This CAN be a hidden process, but first check for legitimate reasons:

			// 1. Skip trusted interceptor processes (LD_PRELOAD may cause /proc discrepancies)
			if strings.Contains(proc.Comm, "prx-proxy") || strings.Contains(proc.Comm, "vigil") {
				continue
			}

			// 2. Skip known sandbox processes (Firefox, containers) that legitimately
			// use PID namespaces making them invisible to simple /proc walks
			if isSandboxProcess(proc.Comm) {
				continue
			}

			// 3. Skip very recently forked processes — /proc enumeration can race
			// with process creation. If we saw the fork < 5 seconds ago, give
			// it a grace period before flagging.
			if time.Duration(uint64(time.Now().UnixNano())-proc.StartNS) < 5*time.Second {
				continue
			}

			// Process is genuinely hidden — potential rootkit
			kernelOnly++

			severity := "warn"
			detail := fmt.Sprintf("Process pid=%d comm=%s visible to kernel but hidden from /proc", pid, proc.Comm)

			// Critical if it's a known rootkit process name
			suspiciousNames := []string{"reptile", "diamorphine", "caraxes", "suterusu", "boopkit", "glrk"}
			for _, name := range suspiciousNames {
				if strings.Contains(strings.ToLower(proc.Comm), name) {
					severity = "critical"
					detail = fmt.Sprintf("SUSPICIOUS process pid=%d comm=%s hidden from /proc (matches known rootkit name)", pid, proc.Comm)
					break
				}
			}

			cvc.statsMu.Lock()
			cvc.stats.Mismatches++
			cvc.stats.ProcessMismatches++
			cvc.statsMu.Unlock()

			if severity == "critical" {
				cvc.alert.CriticalPID(pid, string(models.CatCrossView), "%s", detail)
			} else {
				cvc.alert.WarnPID(pid, string(models.CatCrossView), "%s", detail)
			}
		}
	}

	// Find processes in userspace but NOT in kernel eBPF view
	// This is expected for processes that started before VIGIL
	userOnly := 0
	for pid := range userPIDs {
		if _, ok := procSnapshot[pid]; !ok {
			userOnly++
		}
	}

	if kernelOnly > 0 || userOnly > 0 {
		log.Printf("[VIGIL-CV] process reconcile: kernel_only=%d user_only=%d (kernel=%d user=%d)",
			kernelOnly, userOnly, len(procSnapshot), len(userPIDs))
	}
}

// reconcileConnections compares kernel connection view vs /proc/net/tcp
func (cvc *CrossViewChecker) reconcileConnections(connSnapshot map[string]*ConnectionInfo) {
	// Enumerate /proc/net/tcp for userspace view
	userConns := cvc.enumerateProcNetTCP()

	// Count connections in ESTABLISHED state from eBPF that aren't in /proc/net/tcp
	kernelOnlyConns := 0
	for _, conn := range connSnapshot {
		if conn.NewState != TCPEstablished {
			continue
		}

		key := connKey(conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)

		if !userConns[key] {
			// Connection visible to kernel but NOT in /proc/net/tcp
			kernelOnlyConns++

			// Skip the companion proxy proxy connections (legitimate proxy traffic)
			if conn.DstPort == 8440 || conn.SrcPort == 8440 ||
				conn.DstPort == 8442 || conn.SrcPort == 8442 {
				continue
			}

			// Skip well-known safe ports
			if conn.DstPort == 443 || conn.DstPort == 80 || conn.DstPort == 53 {
				continue
			}

			cvc.statsMu.Lock()
			cvc.stats.Mismatches++
			cvc.stats.ConnMismatches++
			cvc.statsMu.Unlock()

			cvc.alert.WarnPID(conn.PID, string(models.CatCrossView),
				"HIDDEN_CONNECTION: pid=%d %s:%d -> %s:%d visible to kernel but not in /proc/net/tcp",
				conn.PID, conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)
		}
	}

	if kernelOnlyConns > 0 {
		log.Printf("[VIGIL-CV] connection reconcile: kernel_only=%d", kernelOnlyConns)
	}
}

// enumerateProc reads /proc to get the userspace view of PIDs
func (cvc *CrossViewChecker) enumerateProc() map[uint32]bool {
	pids := make(map[uint32]bool)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("[VIGIL-CV] cannot read /proc: %v", err)
		return pids
	}

	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}
		pids[uint32(pid)] = true
	}

	return pids
}

// enumerateProcNetTCP reads /proc/net/tcp for the userspace view of TCP connections
func (cvc *CrossViewChecker) enumerateProcNetTCP() map[string]bool {
	conns := make(map[string]bool)

	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		log.Printf("[VIGIL-CV] cannot read /proc/net/tcp: %v", err)
		return conns
	}

	for _, line := range strings.Split(string(data), "\n") {
		// Format: sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header line
		if fields[0] == "sl" {
			continue
		}

		// Parse local_address and rem_address (hex format: IP:PORT)
		localParts := strings.Split(fields[1], ":")
		remParts := strings.Split(fields[2], ":")
		if len(localParts) != 2 || len(remParts) != 2 {
			continue
		}

		srcPort := parseHex16(localParts[1])
		dstPort := parseHex16(remParts[1])
		srcIP := parseHexIP(localParts[0])
		dstIP := parseHexIP(remParts[0])

		key := connKey(srcIP, srcPort, dstIP, dstPort)
		conns[key] = true
	}

	// Also parse /proc/net/tcp6 if available
	data6, err := os.ReadFile("/proc/net/tcp6")
	if err == nil {
		for _, line := range strings.Split(string(data6), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] == "sl" {
				continue
			}
			localParts := strings.Split(fields[1], ":")
			remParts := strings.Split(fields[2], ":")
			if len(localParts) != 2 || len(remParts) != 2 {
				continue
			}

			srcPort := parseHex16(localParts[1])
			dstPort := parseHex16(remParts[1])
			// IPv6 addresses are in hex format but we'll parse them as IPv4 for now
			srcIP := parseHexIP(localParts[0])
			dstIP := parseHexIP(remParts[0])

			key := connKey(srcIP, srcPort, dstIP, dstPort)
			conns[key] = true
		}
	}

	return conns
}

// parseHexIP converts a hex IP address string to net.IP (little-endian format from /proc)
func parseHexIP(hex string) net.IP {
	if len(hex) != 8 {
		return net.IPv4zero
	}
	val, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return net.IPv4zero
	}
	// /proc/net/tcp stores IPs in little-endian byte order
	b0 := byte(val & 0xFF)
	b1 := byte((val >> 8) & 0xFF)
	b2 := byte((val >> 16) & 0xFF)
	b3 := byte((val >> 24) & 0xFF)
	return net.IPv4(b0, b1, b2, b3)
}

// parseHex16 converts a hex port string to uint16
func parseHex16(hex string) uint16 {
	val, err := strconv.ParseUint(hex, 16, 16)
	if err != nil {
		return 0
	}
	return uint16(val)
}

// GetStats returns current cross-view statistics
func (cvc *CrossViewChecker) GetStats() Stats {
	cvc.mu.RLock()
	defer cvc.mu.RUnlock()
	return cvc.stats
}

// IsEnabled returns whether the cross-view checker is active
func (cvc *CrossViewChecker) IsEnabled() bool {
	return cvc.enabled && !cvc.stub
}

// Close cleanly detaches all tracepoints and closes the collection
func (cvc *CrossViewChecker) Close() {
	if cvc.reader != nil {
		cvc.reader.Close()
	}
	for _, l := range cvc.links {
		l.Close()
	}
	cvc.links = nil
	if cvc.collection != nil {
		cvc.collection.Close()
		cvc.collection = nil
	}
	cvc.enabled = false
	log.Printf("[VIGIL-CV] cross-view integrity checker shut down")
}

// projDir returns the project directory
func projDir() string {
	if dir := os.Getenv("VIGIL_DIR"); dir != "" {
		return dir
	}
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