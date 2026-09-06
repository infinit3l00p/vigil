// Package baseline implements VIGIL's temporal baseline engine.
//
// It collects kernel function execution time samples during a learning phase,
// then uses them as a reference distribution for the Kolmogorov-Smirnov test
// and Welch's t-test during the detection phase.
//
// Academic basis: "Trace of the Times: Rootkit Detection through Temporal
// Anomalies in Kernel Activity" (Landauer et al., ACM DTRAP 2025)
//
// Key design decisions:
//   - Learning phase: configurable duration (default 10 minutes)
//   - Per-function baselines: each kernel function gets its own distribution
//   - Multi-modal awareness: KS test handles multi-modal distributions natively
//   - Sliding window: baseline is periodically refreshed to handle system changes
//   - TCA defense: bounded sample storage, capped at MaxBaselineSamples per function
//   - Graceful degradation: if baseline is too small, detection is deferred
package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/vigil/edr/internal/config"
	"github.com/vigil/edr/internal/ebpf"
)

// FunctionBaseline holds the baseline timing distribution for one kernel function.
type FunctionBaseline struct {
	Name      string  `json:"name"`
	FuncID    uint32  `json:"func_id"`
	Samples   []uint64 `json:"samples"` // Sorted execution times in nanoseconds
	Mean      float64 `json:"mean"`
	StdDev    float64 `json:"std_dev"`
	Median    float64 `json:"median"`
	P5        float64 `json:"p5"`  // 5th percentile
	P95       float64 `json:"p95"` // 95th percentile
	SampleCount int   `json:"sample_count"`
	BuiltAt   time.Time `json:"built_at"`
}

// Baseline manages the collection and persistence of function timing baselines.
type Baseline struct {
	mu        sync.RWMutex
	path      string
	cfg       *config.Config
	functions map[uint32]*FunctionBaseline
	ready     bool
	startTime time.Time
}

// New creates a new baseline manager.
func New(path string, cfg *config.Config) *Baseline {
	return &Baseline{
		path:      path,
		cfg:       cfg,
		functions: make(map[uint32]*FunctionBaseline),
	}
}

// Load reads a previously saved baseline from disk.
func (b *Baseline) Load() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, err := os.ReadFile(b.path)
	if err != nil {
		return fmt.Errorf("read baseline: %w", err)
	}

	var baselines map[uint32]*FunctionBaseline
	if err := json.Unmarshal(data, &baselines); err != nil {
		return fmt.Errorf("parse baseline: %w", err)
	}

	b.functions = baselines
	b.ready = true
	log.Printf("[VIGIL] loaded baseline: %d functions", len(b.functions))
	return nil
}

// Save persists the current baseline to disk.
func (b *Baseline) Save() error {
	// Copy the functions map under lock, then release before marshalling
	b.mu.RLock()
	functionsCopy := make(map[uint32]*FunctionBaseline, len(b.functions))
	for k, v := range b.functions {
		functionsCopy[k] = v
	}
	b.mu.RUnlock()

	data, err := json.MarshalIndent(functionsCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	// Write atomically: temp file + rename
	tmpPath := b.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}

	if err := os.Rename(tmpPath, b.path); err != nil {
		return fmt.Errorf("rename baseline: %w", err)
	}

	log.Printf("[VIGIL] saved baseline: %d functions", len(functionsCopy))
	return nil
}

// IsReady returns whether the baseline has been built or loaded.
func (b *Baseline) IsReady() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ready
}

// FunctionCount returns the number of baselined functions.
func (b *Baseline) FunctionCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.functions)
}

// Learn runs the baseline learning phase, collecting timing samples
// from eBPF probes until sufficient data is gathered.
func (b *Baseline) Learn(ctx context.Context, mgr *ebpf.Manager) {
	b.mu.Lock()
	b.startTime = time.Now()
	b.functions = make(map[uint32]*FunctionBaseline)
	b.mu.Unlock()

	log.Printf("[VIGIL] baseline learning phase started (duration: %v)", b.cfg.LearnDuration)

	// Sample collection loop
	sampleCh := make(chan *ebpf.TimingEvent, 10000)
	done := make(chan struct{})

	// Start event reader — respects ctx so it exits cleanly on cancellation
	go func() {
		defer close(done)
		defer close(sampleCh)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			event, err := mgr.ReadEvent()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			select {
			case sampleCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Collect samples until learning duration expires
	deadline := time.After(b.cfg.LearnDuration)
	for {
		select {
		case event, ok := <-sampleCh:
			if !ok {
				// sampleCh closed by reader goroutine (ctx cancelled)
				<-done
				log.Printf("[VIGIL] learning phase interrupted")
				b.computeBaselines()
				b.ready = true
				b.Save()
				return
			}
			b.addSample(event.FuncID, event.ElapsedNS)
		case <-deadline:
			log.Printf("[VIGIL] learning phase complete, computing baselines...")
			b.computeBaselines()
			b.ready = true
			if err := b.Save(); err != nil {
				log.Printf("[VIGIL] baseline save error: %v", err)
			}
			// Wait for reader goroutine to finish (it will exit on next ctx check)
			<-done
			return
		case <-ctx.Done():
			log.Printf("[VIGIL] learning phase interrupted")
			// Save what we have if we have enough samples
			b.computeBaselines()
			b.ready = true
			b.Save()
			<-done
			return
		}
	}
}

// addSample adds a timing sample to the baseline for a function.
func (b *Baseline) addSample(funcID uint32, elapsedNS uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bl, ok := b.functions[funcID]
	if !ok {
		bl = &FunctionBaseline{
			FuncID:    funcID,
			Name:      functionName(funcID),
			Samples:   make([]uint64, 0, 5000),
		}
		b.functions[funcID] = bl
	}

	// TCA defense: cap sample storage
	if len(bl.Samples) >= 10000 {
		// Random replacement to maintain a representative sample
		idx := rand.Intn(len(bl.Samples))
		bl.Samples[idx] = elapsedNS
	} else {
		bl.Samples = append(bl.Samples, elapsedNS)
	}
}

// computeBaselines computes statistical properties for all functions.
// Applies outlier filtering: values exceeding 10x the p95 are excluded
// from the baseline (these are disk I/O stalls, not rootkit hooks).
func (b *Baseline) computeBaselines() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, bl := range b.functions {
		if len(bl.Samples) < 5000 {
			log.Printf("[VIGIL] function %s: only %d samples (need %d), skipping baseline",
				bl.Name, len(bl.Samples), 5000)
			continue
		}

		// Sort for percentile calculations
		sort.Slice(bl.Samples, func(i, j int) bool {
			return bl.Samples[i] < bl.Samples[j]
		})

		// Outlier filtering: exclude values exceeding 10x the p95.
		// Kernel functions like vfs_read include page faults and disk I/O
		// that can take seconds — these are not rootkit hooks.
		// Rootkit hooks add microseconds to milliseconds, not seconds.
		p95 := percentile(bl.Samples, 95)
		cutoff := p95 * 10.0
		filtered := make([]uint64, 0, len(bl.Samples))
		numOutliers := 0
		for _, s := range bl.Samples {
			if float64(s) <= cutoff {
				filtered = append(filtered, s)
			} else {
				numOutliers++
			}
		}

		// Use filtered samples if we have enough; otherwise fall back to all
		samplesForStats := filtered
		if len(filtered) < 5000 {
			log.Printf("[VIGIL] function %s: only %d samples after outlier filtering (need %d), using unfiltered",
				bl.Name, len(filtered), 5000)
			samplesForStats = bl.Samples
		} else {
			if numOutliers > 0 {
				log.Printf("[VIGIL] function %s: filtered %d outliers (cutoff=%.0fns = 10x p95 %.0fns)",
					bl.Name, numOutliers, cutoff, p95)
			}
		}

		// Re-sort filtered samples
		sort.Slice(samplesForStats, func(i, j int) bool {
			return samplesForStats[i] < samplesForStats[j]
		})

		bl.Samples = samplesForStats
		bl.SampleCount = len(samplesForStats)
		bl.Mean = mean(samplesForStats)
		bl.StdDev = stddev(samplesForStats)
		bl.Median = percentile(samplesForStats, 50)
		bl.P5 = percentile(samplesForStats, 5)
		bl.P95 = percentile(samplesForStats, 95)
		bl.BuiltAt = time.Now()

		log.Printf("[VIGIL] baseline: %s — mean=%.0fns stddev=%.0fns p5=%.0fns p95=%.0fns (n=%d)",
			bl.Name, bl.Mean, bl.StdDev, bl.P5, bl.P95, bl.SampleCount)
	}
}

// GetBaseline returns the baseline for a specific function.
func (b *Baseline) GetBaseline(funcID uint32) (*FunctionBaseline, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bl, ok := b.functions[funcID]
	return bl, ok
}

// GetAllBaselines returns all function baselines.
func (b *Baseline) GetAllBaselines() map[uint32]*FunctionBaseline {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make(map[uint32]*FunctionBaseline, len(b.functions))
	for k, v := range b.functions {
		result[k] = v
	}
	return result
}

// RefreshPeriodically re-collects the baseline at regular intervals.
// This prevents baseline drift: as the system runs, workload patterns change
// (caching warms up, new processes start, etc.). Without refresh, the
// detector would slowly accumulate false positives.
//
// Refresh strategy: blend old and new. We keep 50% of the old baseline
// samples and add fresh samples, so the baseline evolves gradually.
// This prevents sudden shifts while staying responsive to system changes.
func (b *Baseline) RefreshPeriodically(ctx context.Context, mgr *ebpf.Manager, interval time.Duration) {
	log.Printf("[VIGIL] baseline refresh scheduled every %v", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("[VIGIL] refreshing baseline...")

			// Keep 50% of old samples (representative core)
			b.mu.Lock()
			for _, bl := range b.functions {
				halfLen := len(bl.Samples) / 2
				if halfLen > 5000 {
					halfLen = 5000
				}
				bl.Samples = bl.Samples[:halfLen]
				bl.SampleCount = halfLen
			}
			b.mu.Unlock()

			// Collect fresh samples for half the learn duration
			sampleCh := make(chan *ebpf.TimingEvent, 10000)
			refreshDur := b.cfg.LearnDuration / 2
			if refreshDur < time.Minute {
				refreshDur = time.Minute
			}

			readerDone := make(chan struct{})
			go func() {
				defer close(readerDone)
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}

					event, err := mgr.ReadEvent()
					if err != nil {
						select {
						case <-ctx.Done():
							return
						default:
							continue
						}
					}
					select {
					case sampleCh <- event:
					case <-ctx.Done():
						return
					}
				}
			}()

			deadline := time.After(refreshDur)
			samplesCollected := 0
	collect:
			for {
				select {
				case event := <-sampleCh:
					b.addSample(event.FuncID, event.ElapsedNS)
					samplesCollected++
				case <-deadline:
					break collect
				case <-ctx.Done():
					break collect
				}
			}

			// Close sampleCh so the reader goroutine unblocks and exits
			close(sampleCh)
			<-readerDone

			log.Printf("[VIGIL] baseline refresh collected %d new samples", samplesCollected)
			b.computeBaselines()

			if err := b.Save(); err != nil {
				log.Printf("[VIGIL] baseline refresh save error: %v", err)
			}
			log.Printf("[VIGIL] baseline refreshed (%d functions)", b.FunctionCount())
		}
	}
}

// ─── Statistical functions ────────────────────────────────────────

// mean computes the arithmetic mean of a sample of uint64 values.
func mean(samples []uint64) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += float64(s)
	}
	return sum / float64(len(samples))
}

// stddev computes the standard deviation of a sample of uint64 values.
func stddev(samples []uint64) float64 {
	if len(samples) < 2 {
		return 0
	}
	m := mean(samples)
	var sumSq float64
	for _, s := range samples {
		d := float64(s) - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(samples)-1)) // N-1 for sample stddev
}

// percentile computes the p-th percentile of sorted samples.
func percentile(sorted []uint64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := float64(len(sorted)-1) * p / 100.0
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper || upper >= len(sorted) {
		return float64(sorted[lower])
	}
	// Linear interpolation
	frac := idx - float64(lower)
	return float64(sorted[lower])*(1-frac) + float64(sorted[upper])*frac
}

// KSTest performs the two-sample Kolmogorov-Smirnov test.
// Returns the D statistic and whether the null hypothesis is rejected
// at the given significance level alpha.
//
// H0: the two samples come from the same distribution.
// H1: the two samples come from different distributions.
//
// Rootkit hooks can either ADD execution time (slower) or SKIP security
// checks (faster). We compute both D+ and D- and use max(D+, D-) as the
// test statistic (two-sided KS test) to catch both directions.
func KSTest(baseline, window []uint64, alpha float64) (dStatistic float64, rejected bool) {
	if len(baseline) < 10 || len(window) < 10 {
		return 0, false
	}

	n1 := float64(len(baseline))
	n2 := float64(len(window))

	// Explicitly sort inputs (defensive — callers should pre-sort, but don't rely on it)
	sortedBaseline := make([]uint64, len(baseline))
	copy(sortedBaseline, baseline)
	sort.Slice(sortedBaseline, func(i, j int) bool { return sortedBaseline[i] < sortedBaseline[j] })

	sortedWindow := make([]uint64, len(window))
	copy(sortedWindow, window)
	sort.Slice(sortedWindow, func(i, j int) bool { return sortedWindow[i] < sortedWindow[j] })

	// Merge and sort all unique values
	allVals := make([]uint64, 0, len(sortedBaseline)+len(sortedWindow))
	allVals = append(allVals, sortedBaseline...)
	allVals = append(allVals, sortedWindow...)
	sort.Slice(allVals, func(i, j int) bool { return allVals[i] < allVals[j] })

	// Compute empirical CDFs at each unique value using binary search (O(n log n))
	var maxDPlus float64  // D+ = max(CDF1(x) - CDF2(x)) — window shifted RIGHT (slower)
	var maxDMinus float64 // D- = max(CDF2(x) - CDF1(x)) — window shifted LEFT (faster)
	for _, val := range allVals {
		cdf1 := empiricalCDFBinarySearch(sortedBaseline, val)
		cdf2 := empiricalCDFBinarySearch(sortedWindow, val)

		dPlus := cdf1 - cdf2
		dMinus := cdf2 - cdf1
		if dPlus > maxDPlus {
			maxDPlus = dPlus
		}
		if dMinus > maxDMinus {
			maxDMinus = dMinus
		}
	}

	// Two-sided test: use max(D+, D-) as the test statistic
	maxD := math.Max(maxDPlus, maxDMinus)

	// KS critical value: c(alpha) * sqrt((n1+n2) / (n1*n2))
	// For alpha=0.01, c=1.63; for alpha=0.05, c=1.36
	criticalValue := ksCriticalValue(alpha) * math.Sqrt((n1+n2)/(n1*n2))

	return maxD, maxD > criticalValue
}

// empiricalCDFBinarySearch computes the empirical CDF value at x using binary search.
// Requires sorted input. O(log n) per call instead of O(n).
func empiricalCDFBinarySearch(sorted []uint64, x uint64) float64 {
	// Use sort.Search to find the first index where sorted[i] > x
	idx := sort.Search(len(sorted), func(i int) bool {
		return sorted[i] > x
	})
	// idx is the count of elements <= x
	return float64(idx) / float64(len(sorted))
}

// ksCriticalValue returns the KS critical value for a given alpha.
func ksCriticalValue(alpha float64) float64 {
	switch {
	case alpha <= 0.001:
		return 1.95
	case alpha <= 0.01:
		return 1.63
	case alpha <= 0.02:
		return 1.52
	case alpha <= 0.05:
		return 1.36
	case alpha <= 0.10:
		return 1.22
	default:
		return 1.07
	}
}

// WelchTTest performs Welch's t-test for unequal variances.
// Returns the t-statistic and whether the null hypothesis is rejected.
//
// H0: the two samples have the same mean.
// H1: the window sample has a HIGHER mean (rootkit slows things down).
func WelchTTest(baseline, window []uint64, alpha float64) (tStatistic float64, rejected bool) {
	n1 := float64(len(baseline))
	n2 := float64(len(window))

	if n1 < 5 || n2 < 5 {
		return 0, false
	}

	m1 := mean(baseline)
	m2 := mean(window)
	s1 := stddev(baseline)
	s2 := stddev(window)

	// Welch's t-statistic
	se := math.Sqrt(s1*s1/n1 + s2*s2/n2)
	if se == 0 {
		return 0, false
	}

	t := (m2 - m1) / se // Positive = window is slower

	// Welch-Satterthwaite degrees of freedom
	num := (s1*s1/n1 + s2*s2/n2) * (s1*s1/n1 + s2*s2/n2)
	den1 := (s1 * s1 / n1) * (s1 * s1 / n1) / (n1 - 1)
	den2 := (s2 * s2 / n2) * (s2 * s2 / n2) / (n2 - 1)

	if den1+den2 == 0 {
		return 0, false
	}

	df := num / (den1 + den2)

	// One-sided critical value (right tail)
	// t-distribution with df degrees of freedom
	criticalT := tCriticalValue(df, alpha)

	return t, t > criticalT
}

// tCriticalValue returns the one-sided critical t-value for given df and alpha.
// Uses a proper lookup table for one-sided α=0.01 with binary search / interpolation.
//
// Table values (one-sided α=0.01):
//
//	df=1: 31.821, df=2: 6.965, df=3: 4.541, df=4: 3.747, df=5: 3.365,
//	df=6: 3.143, df=7: 2.998, df=8: 2.896, df=9: 2.821, df=10: 2.764,
//	df=15: 2.602, df=20: 2.528, df=25: 2.485, df=30: 2.457,
//	df=40: 2.423, df=60: 2.390, df=120: 2.358, inf: 2.326
func tCriticalValue(df, alpha float64) float64 {
	// This table is for one-sided α=0.01. If a different alpha is requested,
	// we still use these values as the closest approximation.
	_ = alpha // table is for α=0.01

	type entry struct {
		df int
		t  float64
	}

	// Known one-sided α=0.01 t-critical values
	table := []entry{
		{1, 31.821}, {2, 6.965}, {3, 4.541}, {4, 3.747}, {5, 3.365},
		{6, 3.143}, {7, 2.998}, {8, 2.896}, {9, 2.821}, {10, 2.764},
		{15, 2.602}, {20, 2.528}, {25, 2.485}, {30, 2.457},
		{40, 2.423}, {60, 2.390}, {120, 2.358}, {1 << 30, 2.326}, // infinity
	}

	dfInt := int(math.Floor(df))
	if dfInt <= 0 {
		return 31.821 // df=1 fallback
	}

	// Exact match or interpolate between adjacent entries
	for i := 0; i < len(table); i++ {
		if dfInt == table[i].df {
			return table[i].t
		}
		if dfInt < table[i].df {
			if i == 0 {
				return table[0].t // df < 1, use df=1
			}
			// Linear interpolation between table[i-1] and table[i]
			dfLo := float64(table[i-1].df)
			dfHi := float64(table[i].df)
			tLo := table[i-1].t
			tHi := table[i].t
			frac := (float64(dfInt) - dfLo) / (dfHi - dfLo)
			return tLo + frac*(tHi-tLo)
		}
	}

	// df > 120: interpolate between df=120 and infinity
	if dfInt > 120 {
		dfLo := 120.0
		dfHi := float64(1 << 30) // large number representing infinity
		tLo := 2.358
		tHi := 2.326
		// Use 1/df for interpolation (asymptotic approach to normal)
		invDf := 1.0 / float64(dfInt)
		invLo := 1.0 / dfLo
		invHi := 1.0 / dfHi
		frac := (invDf - invLo) / (invHi - invLo)
		return tLo + frac*(tHi-tLo)
	}

	return 2.326 // normal approximation fallback
}

// functionName returns a human-readable name for a function ID.
func functionName(funcID uint32) string {
	for _, fn := range ebpf.DefaultFunctions {
		if fn.ID == funcID {
			return fn.Name
		}
	}
	return fmt.Sprintf("func_%d", funcID)
}