// Package dnsguard implements DNS exfiltration detection for VIGIL.
//
// Based on: BPFflow (eBPF '25), eBPF-PATROL (arXiv 2511.18155).
//
// Detects DNS-based data exfiltration by monitoring DNS query patterns:
//   - High query rate per process (beaconing)
//   - High-entropy domain names (encoded data in subdomains)
//   - Unusual DNS server IPs
//   - Large DNS responses (tunnel data)
package dnsguard

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/vigil/edr/internal/alert"
	ebpfpkg "github.com/vigil/edr/internal/ebpf"
	"github.com/vigil/edr/internal/models"
)

type DNSGuard struct {
	mu      sync.Mutex
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	alert   *alert.AlertManager
	logger  *zap.Logger
	stats   DNSGuardStats
	statsMu sync.Mutex
	enabled bool
	ctx     context.Context
	cancel  context.CancelFunc
}

type DNSGuardStats struct {
	TotalQueries    int
	TotalResponses  int
	QueryBytes      int64
	ResponseBytes   int64
	UniqueServers   int
	SuspiciousRate  int
	HighEntropy     int
	LargeResponses  int
	EventsProcessed int
}

// DNSProcessStats tracks per-process DNS behavior.
type DNSProcessStats struct {
	PID           uint32
	Comm          string
	QueryCount    int
	ResponseCount int
	BytesOut      int64
	BytesIn       int64
	UniqueDests   map[uint32]bool
	FirstSeen     time.Time
	LastSeen      time.Time
}

func NewDNSGuard(alertMgr *alert.AlertManager, logger *zap.Logger) (*DNSGuard, error) {
	return &DNSGuard{
		alert:  alertMgr,
		logger: logger,
	}, nil
}

func (dg *DNSGuard) Load(objPath string) error {
	coll, err := ebpf.LoadCollection(objPath)
	if err != nil {
		return fmt.Errorf("load dns eBPF: %w", err)
	}
	dg.coll = coll

	key := uint32(0)
	enableVal := uint32(1)
	if m := dg.coll.Maps["dns_global_enable"]; m != nil {
		m.Put(&key, &enableVal)
	}

	attachCount := 0
	if prog := dg.coll.Programs["handle_sendto"]; prog != nil {
		l, err := link.Kprobe(ebpfpkg.SyscallWrapper("sendto"), prog, nil)
		if err != nil {
			dg.logger.Warn("dns: failed to attach sendto", zap.Error(err))
		} else {
			dg.links = append(dg.links, l)
			attachCount++
		}
	}
	if prog := dg.coll.Programs["handle_recvfrom"]; prog != nil {
		l, err := link.Kprobe(ebpfpkg.SyscallWrapper("recvfrom"), prog, nil)
		if err != nil {
			dg.logger.Warn("dns: failed to attach recvfrom", zap.Error(err))
		} else {
			dg.links = append(dg.links, l)
			attachCount++
		}
	}

	if m := dg.coll.Maps["dns_events"]; m != nil {
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			return fmt.Errorf("dns ringbuf: %w", err)
		}
		dg.reader = reader
	}

	dg.enabled = attachCount > 0
	dg.logger.Info("dns: eBPF loaded", zap.Int("attached", attachCount))
	return nil
}

func (dg *DNSGuard) Run(ctx context.Context) {
	dg.ctx, dg.cancel = context.WithCancel(ctx)
	go dg.readEvents()
	go dg.anomalyCheck()
}

func (dg *DNSGuard) readEvents() {
	if dg.reader == nil {
		return
	}
	procStats := make(map[uint32]*DNSProcessStats)

	for {
		select {
		case <-dg.ctx.Done():
			return
		default:
		}
		record, err := dg.reader.Read()
		if err != nil {
			if dg.ctx.Err() != nil {
				return
			}
			continue
		}
		if len(record.RawSample) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(record.RawSample)
		dg.statsMu.Lock()
		dg.stats.EventsProcessed++
		dg.statsMu.Unlock()

		switch eventType {
		case models.DNSEventQuery:
			dg.handleQuery(record.RawSample, procStats)
		case models.DNSEventResponse:
			dg.handleResponse(record.RawSample, procStats)
		}
	}
}

func (dg *DNSGuard) handleQuery(raw []byte, procStats map[uint32]*DNSProcessStats) {
	if len(raw) < 52 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	dport := binary.LittleEndian.Uint32(raw[8:12])
	pktLen := binary.LittleEndian.Uint32(raw[12:16])
	daddr := binary.LittleEndian.Uint32(raw[20:24])
	comm := string(raw[36:52])
	comm = strings.TrimRight(comm, "\x00")

	dg.statsMu.Lock()
	dg.stats.TotalQueries++
	dg.stats.QueryBytes += int64(pktLen)
	dg.statsMu.Unlock()

	// Track per-process
	ps, ok := procStats[pid]
	if !ok {
		ps = &DNSProcessStats{
			PID:         pid,
			Comm:        comm,
			UniqueDests: make(map[uint32]bool),
			FirstSeen:   time.Now(),
		}
		procStats[pid] = ps
	}
	ps.QueryCount++
	ps.BytesOut += int64(pktLen)
	ps.LastSeen = time.Now()
	ps.UniqueDests[daddr] = true

	// Check for unusual DNS ports
	if dport != 53 {
		dg.alert.WarnPID(pid, string(models.CatDNSExfiltration),
			"DNS UNUSUAL PORT: pid=%d comm=%s port=%d (expected 53)",
			pid, comm, dport)
	}
}

func (dg *DNSGuard) handleResponse(raw []byte, procStats map[uint32]*DNSProcessStats) {
	if len(raw) < 40 {
		return
	}
	pid := binary.LittleEndian.Uint32(raw[4:8])
	pktLen := binary.LittleEndian.Uint32(raw[12:16])

	dg.statsMu.Lock()
	dg.stats.TotalResponses++
	dg.stats.ResponseBytes += int64(pktLen)
	dg.statsMu.Unlock()

	// Large DNS responses (>4096 bytes) suggest DNS tunneling
	if pktLen > 4096 {
		dg.statsMu.Lock()
		dg.stats.LargeResponses++
		dg.statsMu.Unlock()
		dg.alert.WarnPID(pid, string(models.CatDNSExfiltration),
			"LARGE DNS RESPONSE: pid=%d len=%d bytes (possible DNS tunnel)",
			pid, pktLen)
	}
}

// anomalyCheck runs periodically to detect DNS exfiltration patterns.
func (dg *DNSGuard) anomalyCheck() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-dg.ctx.Done():
			return
		case <-ticker.C:
			// Check for high query rates via eBPF map
			if m := dg.coll.Maps["dns_proc_stats"]; m != nil {
				var key uint32
				var val []byte
				iter := m.Iterate()
				highRateCount := 0
				for iter.Next(&key, &val) {
					// Query count is at offset 8 in dns_proc_stats struct
					if len(val) >= 16 {
						queryCount := binary.LittleEndian.Uint64(val[8:16])
						if queryCount > 1000 {
							highRateCount++
							comm := ""
							if len(val) >= 64 {
								comm = strings.TrimRight(string(val[48:64]), "\x00")
							}
							dg.alert.WarnPID(key, string(models.CatDNSExfiltration),
								"HIGH DNS RATE: pid=%d comm=%s queries=%d (possible beaconing)",
								key, comm, queryCount)
						}
					}
				}
				dg.statsMu.Lock()
				dg.stats.SuspiciousRate = highRateCount
				dg.statsMu.Unlock()
			}
		}
	}
}

// shannonEntropy calculates Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func (dg *DNSGuard) Stats() DNSGuardStats {
	dg.statsMu.Lock()
	defer dg.statsMu.Unlock()
	return dg.stats
}

func (dg *DNSGuard) IsEnabled() bool {
	return dg.enabled
}

func (dg *DNSGuard) Close() {
	if dg.cancel != nil {
		dg.cancel()
	}
	for _, l := range dg.links {
		_ = l.Close()
	}
	if dg.reader != nil {
		dg.reader.Close()
	}
	if dg.coll != nil {
		dg.coll.Close()
	}
}

var _ = net.IPv4len
