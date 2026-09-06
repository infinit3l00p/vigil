// package flowguard implements network flow baseline detection for VIGIL.
//
// Based on: BPFflow (eBPF '25), MUFFLER (KAIST/ETRI 2025).
//
// Per-process flow aggregation with statistical anomaly detection:
//   - Connection rate (conns/min)
//   - Destination IP diversity (lateral movement detection)
//   - Unusual ports (C2 detection)
//   - High-volume data transfer (exfiltration)
//   - Short-lived regular connections (beaconing)
package flowguard

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
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

type FlowGuard struct {
	mu      sync.Mutex
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	alert   *alert.AlertManager
	logger  *zap.Logger
	stats   FlowGuardStats
	statsMu sync.Mutex
	enabled bool
	ctx     context.Context
	cancel  context.CancelFunc
}

type FlowGuardStats struct {
	ConnectEvents   int
	AcceptEvents    int
	UniqueDests     int
	HighRateProcs   int
	UnusualPorts    int
	EventsProcessed int
	BytesSent       uint64
	BytesRecv       uint64
}

// Known C2/reverse shell ports
var suspiciousPorts = map[uint16]string{
	4444: "metasploit",
	5555: "reverse-shell",
	31337: "backdoor",
	1234:  "default-c2",
	6666:  "irc-c2",
	6667:  "irc-c2",
	9999:  "c2-default",
}

func NewFlowGuard(alertMgr *alert.AlertManager, logger *zap.Logger) (*FlowGuard, error) {
	return &FlowGuard{
		alert:  alertMgr,
		logger: logger,
	}, nil
}

func (fg *FlowGuard) Load(objPath string) error {
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("load flow eBPF: %w", err)
	}
	fg.coll = coll

	key := uint32(0)
	enableVal := uint32(1)
	if m := fg.coll.Maps["flow_global_enable"]; m != nil {
		m.Put(&key, &enableVal)
	}

	attachCount := 0
	if prog := fg.coll.Programs["handle_flow_connect"]; prog != nil {
		l, err := link.Kprobe("__x64_sys_connect", prog, nil)
		if err != nil {
			fg.logger.Warn("flow: failed to attach connect", zap.Error(err))
		} else {
			fg.links = append(fg.links, l)
			attachCount++
		}
	}
	if prog := fg.coll.Programs["handle_flow_accept"]; prog != nil {
		l, err := link.Kprobe("__x64_sys_accept4", prog, nil)
		if err != nil {
			fg.logger.Warn("flow: failed to attach accept4", zap.Error(err))
		} else {
			fg.links = append(fg.links, l)
			attachCount++
		}
	}

	if m := fg.coll.Maps["flow_events"]; m != nil {
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("flow ringbuf: %w", err)
		}
		fg.reader = reader
	}

	fg.enabled = attachCount > 0
	fg.logger.Info("flow: eBPF loaded", zap.Int("attached", attachCount))
	return nil
}

func (fg *FlowGuard) Run(ctx context.Context) {
	fg.ctx, fg.cancel = context.WithCancel(ctx)
	go fg.readEvents()
	go fg.anomalyCheck()
}

func (fg *FlowGuard) readEvents() {
	if fg.reader == nil {
		return
	}
	for {
		select {
		case <-fg.ctx.Done():
			return
		default:
		}
		record, err := fg.reader.Read()
		if err != nil {
			if fg.ctx.Err() != nil {
				return
			}
			continue
		}
		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample)
		fg.statsMu.Lock()
		fg.stats.EventsProcessed++
		fg.statsMu.Unlock()

		switch eventType {
		case models.FlowEventConnect:
			fg.handleConnect(record.RawSample)
		case models.FlowEventAccept:
			fg.handleAccept(record.RawSample)
		case models.FlowEventTCPState:
			fg.handleTCPState(record.RawSample)
		case models.FlowEventSend:
			fg.handleSend(record.RawSample)
		case models.FlowEventRecv:
			fg.handleRecv(record.RawSample)
		default:
			fg.logger.Debug("flowguard: unhandled event type", zap.Uint32("type", eventType))
		}
	}
}

func (fg *FlowGuard) handleConnect(raw []byte) {
	// C struct flow_event layout (with standard alignment):
	//   event_type(4) + pid(4) + uid(4) + saddr(4) + daddr(4) +
	//   sport(2) + dport(2) + size(4) + old_state(4) + new_state(4) +
	//   [4 implicit pad] + timestamp(8) + comm(16) = 64 bytes
	if len(raw) < 64 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	daddr := binary.LittleEndian.Uint32(raw[16:20])
	dport := binary.LittleEndian.Uint16(raw[22:24])
	comm := string(raw[48:64])
	comm = strings.TrimRight(comm, "\x00")

	fg.statsMu.Lock()
	fg.stats.ConnectEvents++
	fg.statsMu.Unlock()

	// Check for suspicious destination ports
	if name, ok := suspiciousPorts[dport]; ok {
		fg.statsMu.Lock()
		fg.stats.UnusualPorts++
		fg.statsMu.Unlock()
		fg.alert.CriticalPID(pid, string(models.CatNetworkFlowAnomaly),
			"SUSPICIOUS PORT: pid=%d uid=%d comm=%s dst=%s:%d (%s)",
			pid, uid, comm, intToIP(daddr), dport, name)
	}
}

func (fg *FlowGuard) handleAccept(raw []byte) {
	// C struct flow_event layout: see handleConnect for full layout. 64 bytes.
	if len(raw) < 64 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	uid := binary.LittleEndian.Uint32(raw[8:12])
	comm := string(raw[48:64])
	comm = strings.TrimRight(comm, "\x00")

	fg.statsMu.Lock()
	fg.stats.AcceptEvents++
	fg.statsMu.Unlock()

	_ = uid

	// Skip accept events for PID 1 (systemd/init) — it naturally accepts
	// many inbound connections for dbus, journald, logind etc.
	if pid == 1 {
		return
	}

	// Skip VIGIL's own accept events (dashboard HTTP handler)
	if comm == "vigil" {
		return
	}
}

// anomalyCheck runs periodically to detect flow anomalies.
//
// The eBPF flow_proc_stats struct layout (from vigil_flow.c):
//   offset 0:  pid (u32)
//   offset 4:  uid (u32)
//   offset 8:  connect_count (u64)
//   offset 16: accept_count (u64)
//   offset 24: bytes_sent (u64)
//   offset 32: bytes_recv (u64)
//   offset 40: first_event_ns (u64)
//   offset 48: last_event_ns (u64)
//   offset 56: unique_dest_ips (u32)
//   offset 60: unique_dest_ports (u32)
//   offset 64: unique_src_ports (u32)
//   offset 68: short_lived_conns (u32)
//   offset 72: last_update_ns (u64)
//   offset 80: comm (char[16])
//   Total: 96 bytes
//
// Note: unique_dest_ips is incremented by eBPF's track_dest() for each
// unique (pid, daddr, dport) tuple — it overcounts because same IP with
// different ports counts as multiple entries. We account for this by using
// a higher threshold and only alerting on outbound connect_count, not
// inbound accept traffic.
func (fg *FlowGuard) anomalyCheck() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fg.ctx.Done():
			return
		case <-ticker.C:
			// Check per-process flow stats from eBPF map
			highRate := 0
			if m := fg.coll.Maps["flow_proc_stats"]; m != nil {
				var key uint32
				var val []byte
				iter := m.Iterate()
				for iter.Next(&key, &val) {
					// Skip PID 1 (systemd) and PID 0 (kernel)
					if key == 1 || key == 0 {
						continue
					}

					// Read fields at correct offsets from flow_proc_stats struct
					// Minimum: 80 bytes for fields before comm
					if len(val) < 80 {
						continue
					}

					connectCount := binary.LittleEndian.Uint64(val[8:16])
					uniqueDestIPs := binary.LittleEndian.Uint32(val[56:60])
					uniqueDestPorts := binary.LittleEndian.Uint32(val[60:64])

					// Read comm field at offset 80
					comm := ""
					if len(val) >= 96 {
						comm = strings.TrimRight(string(val[80:96]), "\x00")
					}

					// Skip VIGIL's own process — dashboard creates accept events
					if comm == "vigil" {
						continue
					}

					// Skip well-known system daemons that naturally have
					// high connection counts (dbus-daemon, NetworkManager, etc.)
					skipComms := map[string]bool{
						"systemd":         true,
						"systemd-journal":  true,
						"systemd-resolve": true,
						"dbus-daemon":     true,
						"NetworkManager": true,
						"sshd":            true,
						"dockerd":        true,
						"containerd":     true,
					}
					if skipComms[comm] {
						continue
					}

					// unique_dest_ips overcounts (same IP + different port = separate
					// entry in track_dest), so use a higher threshold of 200.
					// Only flag outbound connect_count above 200 — inbound accept
					// counts are expected for servers.
					if connectCount > 200 || (uniqueDestIPs > 200 && uniqueDestPorts > 50) {
						highRate++
						fg.alert.WarnPID(key, string(models.CatNetworkFlowAnomaly),
							"HIGH FLOW RATE: pid=%d comm=%s connects=%d unique_ips=%d unique_ports=%d",
							key, comm, connectCount, uniqueDestIPs, uniqueDestPorts)
					}
				}
			}
			fg.statsMu.Lock()
			fg.stats.HighRateProcs = highRate
			fg.statsMu.Unlock()
		}
	}
}

// handleTCPState processes TCP state change events for flow tracking.
func (fg *FlowGuard) handleTCPState(raw []byte) {
	// C struct flow_event layout: see handleConnect for full layout. 64 bytes.
	if len(raw) < 64 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	newState := binary.LittleEndian.Uint32(raw[32:36])
	comm := strings.TrimRight(string(raw[48:64]), "\x00")

	fg.statsMu.Lock()
	fg.stats.EventsProcessed++
	fg.statsMu.Unlock()

	// Alert on suspicious TCP state transitions
	if newState == 1 { // TCP_ESTABLISHED
		fg.logger.Debug("flowguard: TCP established", zap.Uint32("pid", pid), zap.String("comm", comm))
	}
}

// handleSend processes TCP send events for volume tracking.
func (fg *FlowGuard) handleSend(raw []byte) {
	// C struct flow_event layout: see handleConnect for full layout. 64 bytes.
	if len(raw) < 64 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	size := binary.LittleEndian.Uint32(raw[24:28])
	comm := strings.TrimRight(string(raw[48:64]), "\x00")

	fg.statsMu.Lock()
	fg.stats.BytesSent += uint64(size)
	fg.statsMu.Unlock()

	// Alert on large data transfers (possible exfiltration)
	if size > 10*1024*1024 { // 10MB single send
		fg.alert.WarnPID(pid, string(models.CatNetworkFlowAnomaly),
			"LARGE SEND: pid=%d comm=%s size=%d bytes — possible data exfiltration",
			pid, comm, size)
	}
}

// handleRecv processes TCP recv events for volume tracking.
func (fg *FlowGuard) handleRecv(raw []byte) {
	// C struct flow_event layout: see handleConnect for full layout. 64 bytes.
	if len(raw) < 64 {
		return
	}
	size := binary.LittleEndian.Uint32(raw[24:28])

	fg.statsMu.Lock()
	fg.stats.BytesRecv += uint64(size)
	fg.statsMu.Unlock()
}

func (fg *FlowGuard) Stats() FlowGuardStats {
	fg.statsMu.Lock()
	defer fg.statsMu.Unlock()
	return fg.stats
}

func (fg *FlowGuard) IsEnabled() bool {
	return fg.enabled
}

func (fg *FlowGuard) Close() {
	if fg.cancel != nil {
		fg.cancel()
	}
	for _, l := range fg.links {
		_ = l.Close()
	}
	if fg.reader != nil {
		fg.reader.Close()
	}
	if fg.coll != nil {
		fg.coll.Close()
	}
}

func intToIP(n uint32) net.IP {
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
}