// package containerguard implements container runtime detection for VIGIL.
//
// Based on: CryptoGuard (ASIACCS 2025), CVE-2024-1086, CVE-2026-23111.
//
// Detects container escape attempts by monitoring namespace transitions:
//   - setns() calls joining host namespaces
//   - unshare() creating user namespaces (privilege escalation)
//   - Container processes gaining capabilities in host namespace
package containerguard

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/models"
)

type ContainerGuard struct {
	mu      sync.Mutex
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	alert   *alert.AlertManager
	logger  *zap.Logger
	stats   ContainerGuardStats
	statsMu sync.Mutex
	enabled bool
	ctx     context.Context
	cancel  context.CancelFunc
}

type ContainerGuardStats struct {
	SetNSEvents    int
	UnshareEvents  int
	NSEscapes      int
	PrivEscAttempts int
	EventsProcessed int
}

func NewContainerGuard(alertMgr *alert.AlertManager, logger *zap.Logger) (*ContainerGuard, error) {
	return &ContainerGuard{
		alert:  alertMgr,
		logger: logger,
	}, nil
}

func (cg *ContainerGuard) Load(objPath string) error {
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("load container eBPF: %w", err)
	}
	cg.coll = coll

	key := uint32(0)
	enableVal := uint32(1)
	if m := cg.coll.Maps["cont_global_enable"]; m != nil {
		m.Put(&key, &enableVal)
	}

	attachCount := 0
	if prog := cg.coll.Programs["handle_cont_setns"]; prog != nil {
		l, err := link.Kprobe("__x64_sys_setns", prog, nil)
		if err != nil {
			cg.logger.Warn("container: failed to attach setns", zap.Error(err))
		} else {
			cg.links = append(cg.links, l)
			attachCount++
		}
	}
	if prog := cg.coll.Programs["handle_cont_unshare"]; prog != nil {
		l, err := link.Kprobe("__x64_sys_unshare", prog, nil)
		if err != nil {
			cg.logger.Warn("container: failed to attach unshare", zap.Error(err))
		} else {
			cg.links = append(cg.links, l)
			attachCount++
		}
	}
	if prog := cg.coll.Programs["handle_cont_fork"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_process_fork", prog, nil)
		if err != nil {
			cg.logger.Warn("container: failed to attach fork tracepoint", zap.Error(err))
		} else {
			cg.links = append(cg.links, l)
			attachCount++
		}
	}
	if prog := cg.coll.Programs["handle_cont_exit"]; prog != nil {
		l, err := link.Tracepoint("sched", "sched_process_exit", prog, nil)
		if err != nil {
			cg.logger.Warn("container: failed to attach exit tracepoint", zap.Error(err))
		} else {
			cg.links = append(cg.links, l)
			attachCount++
		}
	}

	if m := cg.coll.Maps["cont_events"]; m != nil {
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("container ringbuf: %w", err)
		}
		cg.reader = reader
	}

	cg.enabled = attachCount > 0
	cg.logger.Info("container: eBPF loaded", zap.Int("attached", attachCount))
	return nil
}

func (cg *ContainerGuard) Run(ctx context.Context) {
	cg.ctx, cg.cancel = context.WithCancel(ctx)
	go cg.readEvents()
}

func (cg *ContainerGuard) readEvents() {
	if cg.reader == nil {
		return
	}
	for {
		select {
		case <-cg.ctx.Done():
			return
		default:
		}
		record, err := cg.reader.Read()
		if err != nil {
			if cg.ctx.Err() != nil {
				return
			}
			continue
		}
		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample)
		cg.statsMu.Lock()
		cg.stats.EventsProcessed++
		cg.statsMu.Unlock()

		switch eventType {
		case models.ContEventSetNS:
			cg.handleSetNS(record.RawSample)
		case models.ContEventUnshare:
			cg.handleUnshare(record.RawSample)
		case models.ContEventNSEscape:
			cg.handleNSEscape(record.RawSample)
		case models.ContEventNSCreate:
			cg.handleNSCreate(record.RawSample)
		case models.ContEventPrivEsc:
			cg.handlePrivEsc(record.RawSample)
		default:
			cg.logger.Debug("containerguard: unhandled event type", zap.Uint32("type", eventType))
		}
	}
}

func (cg *ContainerGuard) handleSetNS(raw []byte) {
	// C struct cont_ns_event layout:
	//   event_type(4) + pid(4) + uid(4) + nstype(4) + old_nsid(4) +
	//   new_nsid(4) + timestamp(8) + comm(16) = 48 bytes
	if len(raw) < 48 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	nstype := binary.LittleEndian.Uint32(raw[12:16])
	comm := string(raw[32:48])
	comm = strings.TrimRight(comm, "\x00")

	cg.statsMu.Lock()
	cg.stats.SetNSEvents++
	cg.statsMu.Unlock()

	nsNames := decodeNamespaceFlags(nstype)

	// Don't alert on legitimate container runtime processes.
	// runc, snap-confine, and containerd use setns() constantly to manage
	// containers — this is normal operation, not an escape attempt.
	// Only alert if the process is NOT a known container runtime.
	if !isLegitContainerProcess(comm) {
		cg.alert.WarnPID(pid, string(models.CatContainerEscape),
			"SETNS: pid=%d uid=%d comm=%s namespaces=%s",
			pid, uid, comm, nsNames)
	}
}

func (cg *ContainerGuard) handleUnshare(raw []byte) {
	// C struct cont_ns_event layout:
	//   event_type(4) + pid(4) + uid(4) + nstype(4) + old_nsid(4) +
	//   new_nsid(4) + timestamp(8) + comm(16) = 48 bytes
	if len(raw) < 48 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	nstype := binary.LittleEndian.Uint32(raw[12:16])
	comm := string(raw[32:48])
	comm = strings.TrimRight(comm, "\x00")

	cg.statsMu.Lock()
	cg.stats.UnshareEvents++
	// User namespace creation is a privilege escalation vector
	if nstype&0x10000000 != 0 {
		cg.stats.PrivEscAttempts++
	}
	cg.statsMu.Unlock()

	nsNames := decodeNamespaceFlags(nstype)
	if nstype&0x10000000 != 0 {
		cg.alert.CriticalPID(pid, string(models.CatContainerEscape),
			"UNSHARE USER NS: pid=%d uid=%d comm=%s flags=%s (privilege escalation vector)",
			pid, uid, comm, nsNames)
	} else {
		cg.alert.InfoPID(pid, string(models.CatContainerEscape),
			"UNSHARE: pid=%d uid=%d comm=%s namespaces=%s",
			pid, uid, comm, nsNames)
	}
}

func (cg *ContainerGuard) handleNSEscape(raw []byte) {
	// C struct cont_ns_event layout:
	//   event_type(4) + pid(4) + uid(4) + nstype(4) + old_nsid(4) +
	//   new_nsid(4) + timestamp(8) + comm(16) = 48 bytes
	if len(raw) < 48 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	comm := string(raw[32:48])
	comm = strings.TrimRight(comm, "\x00")

	cg.statsMu.Lock()
	cg.stats.NSEscapes++
	cg.statsMu.Unlock()

	cg.alert.CriticalPID(pid, string(models.CatContainerEscape),
		"CONTAINER ESCAPE: pid=%d comm=%s — process escaped container namespace!",
		pid, comm)
}

// handleNSCreate handles namespace creation events.
func (cg *ContainerGuard) handleNSCreate(raw []byte) {
	// C struct cont_ns_event layout:
	//   event_type(4) + pid(4) + uid(4) + nstype(4) + old_nsid(4) +
	//   new_nsid(4) + timestamp(8) + comm(16) = 48 bytes
	if len(raw) < 48 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	nstype := binary.LittleEndian.Uint32(raw[12:16])
	comm := strings.TrimRight(string(raw[32:48]), "\x00")

	// User namespace creation is a privilege escalation vector
	if nstype & 0x10000000 != 0 { // CLONE_NEWUSER
		cg.statsMu.Lock()
		cg.stats.PrivEscAttempts++
		cg.statsMu.Unlock()
		tg := cg.alert
		if tg != nil {
			tg.WarnPID(pid, string(models.CatContainerEscape),
				"USER NAMESPACE CREATED: pid=%d uid=%d comm=%s nstype=0x%x — possible privilege escalation",
				pid, uid, comm, nstype)
		}
	}
}

// handlePrivEsc handles privilege escalation events in containers.
func (cg *ContainerGuard) handlePrivEsc(raw []byte) {
	// C struct cont_ns_event layout:
	//   event_type(4) + pid(4) + uid(4) + nstype(4) + old_nsid(4) +
	//   new_nsid(4) + timestamp(8) + comm(16) = 48 bytes
	if len(raw) < 48 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	comm := strings.TrimRight(string(raw[32:48]), "\x00")

	cg.statsMu.Lock()
	cg.stats.PrivEscAttempts++
	cg.statsMu.Unlock()

	cg.alert.CriticalPID(pid, string(models.CatContainerEscape),
		"PRIVILEGE ESCALATION: pid=%d uid=%d comm=%s — container privilege escalation detected!",
		pid, uid, comm)
}

func (cg *ContainerGuard) Stats() ContainerGuardStats {
	cg.statsMu.Lock()
	defer cg.statsMu.Unlock()
	return cg.stats
}

func (cg *ContainerGuard) IsEnabled() bool {
	return cg.enabled
}

func (cg *ContainerGuard) Close() {
	if cg.cancel != nil {
		cg.cancel()
	}
	for _, l := range cg.links {
		_ = l.Close()
	}
	if cg.reader != nil {
		cg.reader.Close()
	}
	if cg.coll != nil {
		cg.coll.Close()
	}
}

// isLegitContainerProcess returns true for processes that legitimately
// use setns() as part of normal container runtime operations.
// These should not generate CONTAINER_ESCAPE alerts.
func isLegitContainerProcess(comm string) bool {
	legit := []string{
		"runc",           // OCI container runtime
		"runc:[",          // runc child processes (runc:[1:CHILD], runc:[2:INIT])
		"snap-confine",   // Snap app confinement (uses setns for namespace enter)
		"containerd",     // containerd runtime
		"containerd-shim", // containerd shim
		"dockerd",        // Docker daemon
		"docker-init",    // Docker init
		"podman",         // Podman runtime
		"crun",           // C container runtime
		"youki",          // Rust container runtime
		"systemd-nspawn", // systemd container spawning
		"unshare",        // unshare command (used by Snap, systemd
		"firefox",        // Firefox uses CLONE_NEWPID for content sandbox
		"gnome-shell",    // GNOME session isolation
		"snap-update-ns", // Snap namespace update
		"systemd-timed",  // systemd timer namespace
	}
	for _, l := range legit {
		if strings.HasPrefix(comm, l) || comm == l {
			return true
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