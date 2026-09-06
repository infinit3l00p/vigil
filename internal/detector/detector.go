// Package detector implements VIGIL's anomaly detection engine.
//
// It reads timing events from the eBPF ringbuf, maintains sliding windows
// of recent timing samples, and applies statistical tests (KS test + Welch's
// t-test) to detect rootkit-induced timing shifts.
//
// Detection methodology (Trace of the Times, DTRAP 2025):
//   1. Maintain a sliding window of recent timing samples per function
//   2. Compare window distribution against baseline using KS test
//   3. Compare window mean against baseline mean using Welch's t-test
//   4. Alert only when BOTH tests reject H0 for KSConsecutiveHits windows
//   5. One-sided tests: only alert on RIGHT shifts (slower = rootkit hook)
//
// TCA defense (arXiv 2025):
//   - Bounded window sizes (MaxBaselineSamples)
//   - Rate-limited event processing (per-function)
//   - Backpressure: if detection falls behind, skip events gracefully
package detector

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/vigil/edr/internal/alert"
	"github.com/vigil/edr/internal/baseline"
	"github.com/vigil/edr/internal/config"
	"github.com/vigil/edr/internal/ebpf"
)

// DetectionResult holds the outcome of a single detection cycle.
type DetectionResult struct {
	FuncID      uint32
	FuncName    string
	KSRejected  bool     // KS test rejected H0
	WelchRejected bool   // Welch's t-test rejected H0
	KSD         float64  // KS D-statistic
	WelchT      float64  // Welch's t-statistic
	BaselineMean float64 // Baseline mean (nanoseconds)
	WindowMean  float64  // Window mean (nanoseconds)
	SampleCount int      // Samples in current window
}

// Detector runs the temporal anomaly detection loop.
type Detector struct {
	mgr       *ebpf.Manager
	alrt      *alert.AlertManager
	cfg       *config.Config
	eventReader func() (*ebpf.TimingEvent, error) // Optional override for test mode

	mu      sync.RWMutex
	windows map[uint32]*slidingWindow  // Per-function timing windows
	hits    map[uint32]int             // Consecutive hit counter per function
}

// slidingWindow maintains a bounded window of recent timing samples.
type slidingWindow struct {
	samples []uint64
	head    int
	size   int
	cap    int
}

func newSlidingWindow(cap int) *slidingWindow {
	return &slidingWindow{
		samples: make([]uint64, cap),
		head:    0,
		size:    0,
		cap:     cap,
	}
}

func (w *slidingWindow) add(val uint64) {
	w.samples[w.head] = val
	w.head = (w.head + 1) % w.cap
	if w.size < w.cap {
		w.size++
	}
}

func (w *slidingWindow) snapshot() []uint64 {
	result := make([]uint64, w.size)
	for i := 0; i < w.size; i++ {
		idx := (w.head - w.size + i + w.cap) % w.cap
		result[i] = w.samples[idx]
	}
	return result
}

// New creates a new detection engine.
func New(mgr *ebpf.Manager, alrt *alert.AlertManager, cfg *config.Config) *Detector {
	return &Detector{
		mgr:     mgr,
		alrt:    alrt,
		cfg:     cfg,
		windows: make(map[uint32]*slidingWindow),
		hits:    make(map[uint32]int),
	}
}

// SetEventReader sets a custom event reader for test mode.
// When set, this function is called instead of mgr.ReadEvent().
func (d *Detector) SetEventReader(fn func() (*ebpf.TimingEvent, error)) {
	d.eventReader = fn
}

// RunDetection starts the detection loop. It reads events from the eBPF
// ringbuf, accumulates them in sliding windows, and runs statistical tests
// at the configured interval.
func (d *Detector) RunDetection(ctx context.Context, bl *baseline.Baseline) {
	log.Printf("[VIGIL] detection engine started (interval: %v)", d.cfg.DetectionInterval)

	// Reset state from any previous run so stale hits/windows don't carry over
	d.mu.Lock()
	d.hits = make(map[uint32]int)
	d.windows = make(map[uint32]*slidingWindow)
	d.mu.Unlock()

	// Start event reader goroutine
	eventCh := make(chan *ebpf.TimingEvent, 10000)
	go d.readEvents(ctx, eventCh)

	// Detection ticker
	ticker := time.NewTicker(d.cfg.DetectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[VIGIL] detection engine shutting down")
			return

		case event := <-eventCh:
			d.addEvent(event)

		case <-ticker.C:
			d.detect(bl)
		}
	}
}

// readEvents reads timing events from the eBPF ringbuf (or test injector)
// and sends them to the event channel. Implements backpressure: if the
// channel is full, events are dropped (better than crashing the pipeline).
//
// Error classification: tracks consecutive errors. After 100 consecutive
// errors, logs CRITICAL and exits (the ringbuf or eBPF map is likely gone).
func (d *Detector) readEvents(ctx context.Context, ch chan<- *ebpf.TimingEvent) {
	consecutiveErrors := 0
	const maxConsecutiveErrors = 100

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !d.mgr.IsEnabled() {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		var event *ebpf.TimingEvent
		var err error

		if d.eventReader != nil {
			event, err = d.eventReader()
		} else {
			event, err = d.mgr.ReadEvent()
		}

		if err != nil {
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				log.Printf("[VIGIL] CRITICAL: readEvents encountered %d consecutive errors, exiting goroutine", consecutiveErrors)
				return
			}
			// Ringbuf closed or error — back off briefly
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Reset counter on successful read
		consecutiveErrors = 0

		select {
		case ch <- event:
			// Event sent successfully
		default:
			// Channel full — drop event (backpressure)
			// This is intentional TCA defense: bounded buffers prevent
			// telemetry flooding from crashing the detection engine
		}
	}
}

// addEvent adds a timing event to the appropriate sliding window.
// BUG-031: If the windows map exceeds 20 entries, skip unknown FuncIDs
// to prevent unbounded growth from noise/unknown functions.
func (d *Detector) addEvent(event *ebpf.TimingEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	w, ok := d.windows[event.FuncID]
	if !ok {
		// Max funcs check: prevent unbounded growth of the windows map
		if len(d.windows) >= 20 {
			return // Skip unknown FuncIDs when map is full
		}
		w = newSlidingWindow(10000)
		d.windows[event.FuncID] = w
	}

	w.add(event.ElapsedNS)
}

// detect runs statistical tests on all functions with sufficient data.
// Outlier filtering: window samples exceeding 10x baseline p95 are excluded
// (disk I/O stalls, not rootkit hooks). Rootkit hooks add μs-ms, not seconds.
//
// BUG-019: Window snapshots are copied under lock, then the lock is released
// before running KS test and Welch t-test on the copies. This allows events
// to continue flowing into windows during detection.
func (d *Detector) detect(bl *baseline.Baseline) {
	// Phase 1: Copy window snapshots under lock
	type windowCopy struct {
		funcID uint32
		samples []uint64
	}
	baselines := bl.GetAllBaselines()

	d.mu.Lock()
	windowsToTest := make([]windowCopy, 0, len(d.windows))
	for funcID, window := range d.windows {
		if window.size < 5000 {
			continue // Not enough samples yet
		}

		baseFn, ok := baselines[funcID]
		if !ok {
			continue // No baseline for this function
		}

		if len(baseFn.Samples) < 5000 {
			continue // Baseline too small
		}

		// BUG-034: Skip functions where baseline P95 or Mean is 0
		// (no meaningful comparison possible — would cause div-by-zero or
		// false positives from outlier filtering with cutoff=0)
		if baseFn.P95 == 0 || baseFn.Mean == 0 {
			continue
		}

		// Copy window snapshot under lock
		snap := window.snapshot()
		windowsToTest = append(windowsToTest, windowCopy{
			funcID:  funcID,
			samples: snap,
		})
	}
	d.mu.Unlock()

	// Phase 2: Run statistical tests on copies without holding the lock
	for _, wc := range windowsToTest {
		baseFn := baselines[wc.funcID]

		// Outlier filtering on window samples: exclude values exceeding 10x baseline p95.
		// This removes disk I/O stalls (seconds) that would otherwise make
		// Welch's t-test meaningless. Rootkit hooks add microseconds, not seconds.
		cutoff := baseFn.P95 * 10.0
		filteredWindow := make([]uint64, 0, len(wc.samples))
		for _, s := range wc.samples {
			if float64(s) <= cutoff {
				filteredWindow = append(filteredWindow, s)
			}
		}

		// If too many outliers (>50%), keep all samples (something unusual is happening)
		if len(filteredWindow) < len(wc.samples)/2 {
			filteredWindow = wc.samples
		} else if len(filteredWindow) < 30 {
			// Need at least 30 samples for meaningful statistics
			filteredWindow = wc.samples
		}

		// Run KS test (two-sided: catches both slower and faster shifts)
		dStat, ksRejected := baseline.KSTest(baseFn.Samples, filteredWindow, 0.01)

		// Run Welch's t-test (one-sided: window mean > baseline mean)
		tStat, welchRejected := baseline.WelchTTest(baseFn.Samples, filteredWindow, 0.005)

		result := DetectionResult{
			FuncID:        wc.funcID,
			FuncName:      baseFn.Name,
			KSRejected:    ksRejected,
			WelchRejected: welchRejected,
			KSD:           dStat,
			WelchT:        tStat,
			BaselineMean:  baseFn.Mean,
			WindowMean:    windowMean(filteredWindow),
			SampleCount:   len(filteredWindow),
		}

		if ksRejected && welchRejected {
			shift := percentIncrease(result.BaselineMean, result.WindowMean)

			// Minimum shift threshold: even if KS and Welch both reject, a small
			// timing shift (<50% by default) is normal load variation, not a rootkit.
			// Rootkit hooks add 500μs+ of latency (v0.2 test: 500μs on vfs_read
			// gave D=1.0, t=3.49). A 2-3μs shift under load is measurement noise.
			if shift < d.cfg.MinShiftPercent {
				d.alrt.Debug("SHIFT_BELOW_THRESHOLD",
					"function %s: KS D=%.4f, Welch t=%.2f, shift=%.1f%% (below %.0f%% threshold) — likely load variation",
					result.FuncName, result.KSD, result.WelchT, shift, d.cfg.MinShiftPercent)
				d.mu.Lock()
				d.hits[wc.funcID] = 0 // reset, not a real threat
				d.mu.Unlock()
				continue
			}

			d.mu.Lock()
			d.hits[wc.funcID]++
			hitCount := d.hits[wc.funcID]
			d.mu.Unlock()

			if hitCount >= 3 {
				d.alrt.CriticalPID(0, "TEMPORAL_ANOMALY",
					"kernel function %s shows timing anomaly: KS D=%.4f (p<%.3f), Welch t=%.2f (p<%.3f), baseline_mean=%.0fns window_mean=%.0fns (+%.1f%%), consecutive_hits=%d",
					result.FuncName, result.KSD, 0.01, result.WelchT, 0.005,
					result.BaselineMean, result.WindowMean,
					shift,
					hitCount)
			}
		} else {
			// Reset consecutive hit counter
			d.mu.Lock()
			d.hits[wc.funcID] = 0
			d.mu.Unlock()

			// Debug logging
			if ksRejected || welchRejected {
				d.alrt.Debug("PARTIAL_ANOMALY",
					"function %s: KS rejected=%v D=%.4f, Welch rejected=%v t=%.2f (need both)",
					result.FuncName, result.KSRejected, result.KSD,
					result.WelchRejected, result.WelchT)
			}
		}
	}
}

// windowMean computes the mean of current window samples.
func windowMean(samples []uint64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	return sum / float64(len(samples))
}

// percentIncrease computes the percentage increase from baseline to window.
func percentIncrease(baseline, window float64) float64 {
	if baseline == 0 {
		return 0
	}
	return ((window - baseline) / baseline) * 100
}