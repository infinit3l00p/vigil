// package ttyguard implements TTY input surveillance detection for VIGIL.
//
// Based on: Kernel Rootkit Detection Taxonomy (arXiv 2304.00473),
// HookChain (arXiv 2024).
//
// Detects when something is reading TTY/terminal input that shouldn't be:
//   - Software keyloggers (reading /dev/input/* or ptmx)
//   - SSH session hijacking (reading another user's pty)
//   - Unusual processes reading TTY (web server, daemon)
package ttyguard

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

type TTYGuard struct {
	mu      sync.Mutex
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	alert   *alert.AlertManager
	logger  *zap.Logger
	stats   TTYGuardStats
	statsMu sync.Mutex
	enabled bool
	ctx     context.Context
	cancel  context.CancelFunc
}

type TTYGuardStats struct {
	TTYReadEvents   int
	TTYWriteEvents  int
	PTYWriteEvents  int
	SuspiciousReads int
	EventsProcessed int
}

func NewTTYGuard(alertMgr *alert.AlertManager, logger *zap.Logger) (*TTYGuard, error) {
	return &TTYGuard{
		alert:  alertMgr,
		logger: logger,
	}, nil
}

func (tg *TTYGuard) Load(objPath string) error {
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("load tty eBPF: %w", err)
	}
	tg.coll = coll

	key := uint32(0)
	enableVal := uint32(1)
	if m := tg.coll.Maps["tty_global_enable"]; m != nil {
		m.Put(&key, &enableVal)
	}

	attachCount := 0
	if prog := tg.coll.Programs["handle_n_tty_read"]; prog != nil {
		l, err := link.Kprobe("n_tty_read", prog, nil)
		if err != nil {
			tg.logger.Warn("tty: failed to attach n_tty_read", zap.Error(err))
		} else {
			tg.links = append(tg.links, l)
			attachCount++
		}
	}
	if prog := tg.coll.Programs["handle_n_tty_write"]; prog != nil {
		l, err := link.Kprobe("n_tty_write", prog, nil)
		if err != nil {
			tg.logger.Warn("tty: failed to attach n_tty_write", zap.Error(err))
		} else {
			tg.links = append(tg.links, l)
			attachCount++
		}
	}
	if prog := tg.coll.Programs["handle_pty_write"]; prog != nil {
		l, err := link.Kprobe("pty_write", prog, nil)
		if err != nil {
			tg.logger.Warn("tty: failed to attach pty_write", zap.Error(err))
		} else {
			tg.links = append(tg.links, l)
			attachCount++
		}
	}

	if m := tg.coll.Maps["tty_events"]; m != nil {
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("tty ringbuf: %w", err)
		}
		tg.reader = reader
	}

	tg.enabled = attachCount > 0
	tg.logger.Info("tty: eBPF loaded", zap.Int("attached", attachCount))
	return nil
}

func (tg *TTYGuard) Run(ctx context.Context) {
	tg.ctx, tg.cancel = context.WithCancel(ctx)
	go tg.readEvents()
}

func (tg *TTYGuard) readEvents() {
	if tg.reader == nil {
		return
	}
	for {
		select {
		case <-tg.ctx.Done():
			return
		default:
		}
		record, err := tg.reader.Read()
		if err != nil {
			if tg.ctx.Err() != nil {
				return
			}
			continue
		}
		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample)
		tg.statsMu.Lock()
		tg.stats.EventsProcessed++
		tg.statsMu.Unlock()

		switch eventType {
		case models.TTYEventRead:
			tg.handleTTYRead(record.RawSample)
		case models.TTYEventWrite:
			tg.handleTTYWrite(record.RawSample)
		case models.TTYEventPtyWrite:
			tg.handlePTYWrite(record.RawSample)
		case models.TTYEventInputRead:
			tg.handleInputRead(record.RawSample)
		default:
			tg.logger.Debug("ttyguard: unhandled event type", zap.Uint32("type", eventType))
		}
	}
}

func (tg *TTYGuard) handleTTYRead(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	readCount := binary.LittleEndian.Uint64(raw[16:24])
	comm := string(raw[24:40])
	comm = strings.TrimRight(comm, "\x00")

	tg.statsMu.Lock()
	tg.stats.TTYReadEvents++
	tg.statsMu.Unlock()

	// Suspicious: daemon processes reading TTY
	suspiciousComms := []string{"nginx", "apache2", "httpd", "crond", "dbus-daemon", "docker"}
	for _, sc := range suspiciousComms {
		if comm == sc {
			tg.statsMu.Lock()
			tg.stats.SuspiciousReads++
			tg.statsMu.Unlock()
			tg.alert.CriticalPID(pid, string(models.CatTTYSurveillance),
				"SUSPICIOUS TTY READ: pid=%d uid=%d comm=%s reads=%d — daemon reading terminal input!",
				pid, uid, comm, readCount)
			return
		}
	}

	tg.alert.WarnPID(pid, string(models.CatTTYSurveillance),
		"TTY READ: pid=%d uid=%d comm=%s reads=%d",
		pid, uid, comm, readCount)
}

func (tg *TTYGuard) Stats() TTYGuardStats {
	tg.statsMu.Lock()
	defer tg.statsMu.Unlock()
	return tg.stats
}

func (tg *TTYGuard) IsEnabled() bool {
	return tg.enabled
}

func (tg *TTYGuard) Close() {
	if tg.cancel != nil {
		tg.cancel()
	}
	for _, l := range tg.links {
		_ = l.Close()
	}
	if tg.reader != nil {
		tg.reader.Close()
	}
	if tg.coll != nil {
		tg.coll.Close()
	}
}

// handleTTYWrite processes TTY write events (terminal output).
func (tg *TTYGuard) handleTTYWrite(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	writeCount := binary.LittleEndian.Uint64(raw[16:24])
	comm := strings.TrimRight(string(raw[24:40]), "\x00")

	tg.statsMu.Lock()
	tg.stats.EventsProcessed++
	tg.statsMu.Unlock()

	// Alert on suspicious write patterns (screen scraping)
	if writeCount > 1000 {
		tg.alert.WarnPID(pid, string(models.CatTTYSurveillance),
			"HIGH TTY WRITE VOLUME: pid=%d uid=%d comm=%s writes=%d — possible screen scraping",
			pid, uid, comm, writeCount)
	}
}

// handlePTYWrite processes PTY master write events (pty snooping).
func (tg *TTYGuard) handlePTYWrite(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	comm := strings.TrimRight(string(raw[24:40]), "\x00")

	tg.statsMu.Lock()
	tg.stats.EventsProcessed++
	tg.statsMu.Unlock()

	// PTY writes from non-shell processes are suspicious
	suspiciousComms := []string{"nginx", "apache2", "httpd", "crond", "docker"}
	for _, sc := range suspiciousComms {
		if comm == sc {
			tg.alert.CriticalPID(pid, string(models.CatTTYSurveillance),
				"SUSPICIOUS PTY WRITE: pid=%d uid=%d comm=%s — daemon writing to PTY master!",
				pid, uid, comm)
			return
		}
	}
}

// handleInputRead processes /dev/input read events (evdev keylogger).
func (tg *TTYGuard) handleInputRead(raw []byte) {
	if len(raw) < 44 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	comm := strings.TrimRight(string(raw[24:40]), "\x00")

	// Reading /dev/input/event* is highly suspicious for non-input daemons
	allowedInputReaders := []string{"Xorg", "Xwayland", "gnome-shell", "kwin", "libinput", "systemd-udevd"}
	for _, ar := range allowedInputReaders {
		if comm == ar {
			return // legitimate input reader
		}
	}

	tg.alert.CriticalPID(pid, string(models.CatTTYSurveillance),
		"INPUT DEVICE READ: pid=%d uid=%d comm=%s — process reading /dev/input (possible keylogger)!",
		pid, uid, comm)
}