# VIGIL EDR Security Audit Report

**Date:** 2026-06-24  
**Auditor:** Independent security review  
**Scope:** 15 Go source files (11 detection modules, 4 response engine files) + models.go  

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 12 |
| HIGH | 18 |
| MEDIUM | 16 |
| LOW | 8 |
| **Total** | **54** |

---

## CRITICAL Findings

### BUG-001: Command Injection via PID in nftables Rule
- **File:** `internal/response/network_isolator.go`
- **Category:** Security
- **Severity:** CRITICAL
- **Description:** The `Isolate()` method constructs an nftables rule using `fmt.Sprintf("meta cgroupv2 %d", pid)` and passes it to `exec.Command("nft", args...)`. While `pid` is a `uint32` (preventing classic shell injection), the broader issue is that `exec.Command("nft", ...)` is called with no validation that the `nft` binary is the genuine system binary. An attacker who controls PATH (e.g., via a compromised environment or cgroup namespace) could substitute a malicious `nft` binary. More importantly, the `cgroupMatch` string is built via `fmt.Sprintf` and passed as separate args, but the **`Restore()` method doesn't actually delete the nftables rule** — it only lists the chain. This means `Restore()` is a no-op: isolated processes remain isolated forever, and the in-memory `isolated` map is cleared while the kernel-level rule persists.
- **Impact:** (1) Persistent network isolation that can never be reversed through the API. (2) Accumulating nftables rules on every Isolate call. (3) An attacker could exploit the accumulated rules to deny service to legitimate processes if cgroup IDs are reused.
- **Fix:** Use `nft`'s JSON API or parse the `nft list chain` output to find the rule handle, then `nft delete rule ip <table> <chain> <handle>`. Alternatively, use `nft -f` with a script file for atomic operations. Use `exec.LookPath("nft")` to resolve the absolute path at init time and store it. Consider using Go-native nftables libraries (e.g., `google/nftables`) to avoid shell execution entirely.

### BUG-002: eBPF Link Leak in Lineage Checker
- **File:** `internal/lineage/lineage.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** In `Load()`, eBPF links are created via `link.Kprobe()` and `link.Tracepoint()` but assigned to `_ = l` (discarded). The `lc.links` slice is never populated. The `Close()` method only closes `lc.reader` and `lc.coll` — it never closes the kprobe/tracepoint links. Each leaked link keeps a BPF program attached in the kernel. If `Load()` is called multiple times (e.g., on reload), links accumulate indefinitely.
- **Impact:** BPF program attachment leak. Each leaked link holds a reference to a BPF program and keeps it attached in the kernel. Over time, this exhausts kernel resources (BPF instruction limit, attachment slots), causes duplicate event delivery (multiple attachments to the same probe), and makes it impossible to cleanly unload VIGIL.
- **Fix:** Store links in a `[]link.Link` slice on `LineageChecker` and close them in `Close()`. Change `_ = l` to `lc.links = append(lc.links, l)`.

### BUG-003: eBPF Link Leak in BPF Integrity Checker
- **File:** `internal/bpfintegrity/bpfintegrity.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** Same pattern as BUG-002. In `Load()`, `link.Kprobe()` and `link.Tracepoint()` results are assigned to `_ = l`. The links are never stored or closed. `Close()` only closes the reader and collection.
- **Impact:** Same as BUG-002 — permanent kernel BPF attachment leaks, resource exhaustion, duplicate events.
- **Fix:** Add a `links []link.Link` field, append each created link, and close all links in `Close()`.

### BUG-004: eBPF Link Leak in DNS Guard
- **File:** `internal/dnsguard/dnsguard.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** Same pattern. `link.Kprobe()` results assigned to `_ = l`, never stored or closed.
- **Impact:** Same as BUG-002.
- **Fix:** Same pattern — store and close links.

### BUG-005: eBPF Link Leak in TTY Guard
- **File:** `internal/ttyguard/ttyguard.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** Same pattern. `link.Kprobe()` results assigned to `_ = l`, never stored or closed.
- **Impact:** Same as BUG-002.
- **Fix:** Same pattern — store and close links.

### BUG-006: eBPF Link Leak in Container Guard
- **File:** `internal/containerguard/containerguard.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** Same pattern. `link.Kprobe()` and `link.Tracepoint()` results assigned to `_ = l`, never stored or closed.
- **Impact:** Same as BUG-002.
- **Fix:** Same pattern — store and close links.

### BUG-007: eBPF Link Leak in Flow Guard
- **File:** `internal/flowguard/flowguard.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** Same pattern. `link.Kprobe()` results assigned to `_ = l`, never stored or closed.
- **Impact:** Same as BUG-002.
- **Fix:** Same pattern — store and close links.

### BUG-008: PID Reuse Attack in Response Engine
- **File:** `internal/response/response.go`
- **Category:** Security
- **Severity:** CRITICAL
- **Description:** The `HandleAlert()` method checks `os.Getpid() == int(pid)` for self-targeting protection, but there is a TOCTOU race between this check and the subsequent `executeAction()` call. Between the check and the action, the target process could exit and its PID could be recycled by the kernel. The `killProcess()` function sends SIGTERM to whatever process currently holds that PID. Similarly, `CgroupFreezer.Freeze()` writes the PID to `cgroup.procs` — if the PID has been recycled, an innocent process gets frozen/killed. The `EvidenceCapture` captures the wrong process's data. None of the response actions verify that the target PID still corresponds to the original offending process (e.g., by checking `/proc/[pid]/starttime` against a timestamp captured at detection time).
- **Impact:** An innocent process could be killed, frozen, or network-isolated. In a worst case, an attacker could deliberately trigger detections, time their process exit with PID recycling, and cause VIGIL to attack a system process (e.g., PID 1 systemd), causing system instability.
- **Fix:** Capture the target process's starttime (field 22 in `/proc/[pid]/stat`) at detection time. Before executing any response action, re-read `/proc/[pid]/stat` and verify the starttime matches. If it doesn't, skip the action and log a warning. Also verify the process comm/exe hasn't changed.

### BUG-009: Path Traversal in Evidence Capture
- **File:** `internal/response/evidence_capture.go`
- **Category:** Security
- **Severity:** CRITICAL
- **Description:** The `evidencePath` is constructed from `pid`, `attackType`, and `timestamp` — none of which are sanitized. While `pid` is a `uint32` and `timestamp` is a fixed-format string, `attackType` is a string that flows from `ClassifyAlert()` which maps alert categories to `AttackType` constants. However, if an attacker can inject an alert with a crafted category string (e.g., via a compromised detection module), the `attackType` string could contain path traversal sequences (`../../`). The `filepath.Join()` call would resolve these, potentially writing evidence files to arbitrary locations. Additionally, the `procFiles` list contains `" personality"` with a leading space — this is a typo that will cause `/proc/[pid]/ personality` (with leading space) to always fail to open.
- **Impact:** Path traversal could allow evidence files to be written to arbitrary directories. If the evidence directory is predictable, an attacker could overwrite system files. The `" personality"` typo means personality is never captured.
- **Fix:** Sanitize `attackType` by rejecting or replacing any path-unsafe characters. Use `filepath.Clean()` and validate the result is within `evidenceDir`. Fix the `" personality"` typo to `"personality"`.

### BUG-010: Network Isolator Restore Is a No-Op
- **File:** `internal/response/network_isolator.go`
- **Category:** Logic Error
- **Severity:** CRITICAL
- **Description:** The `Restore()` method deletes the PID from the in-memory `isolated` map and runs `nft list chain ip vigil isolate` — but it never actually deletes the nftables rule. The `nft list chain` command only displays rules; it does not delete them. As a result, once a process is network-isolated, the nftables rule persists in the kernel forever. The in-memory state says "not isolated" while the kernel still drops all traffic.
- **Impact:** Permanently broken network access for any process that was ever isolated. Accumulating nftables rules cause kernel-level performance degradation. An attacker could trigger repeated isolations to exhaust nftables rule limits.
- **Fix:** Parse the output of `nft list chain` to find the rule handle matching this PID's cgroup, then run `nft delete rule ip <table> <chain> <handle>`. Alternatively, use a unique comment/marking on each rule for easier deletion. Consider using `google/nftables` Go library for programmatic rule management.

### BUG-011: Unbounded Process Tracking — Memory Exhaustion
- **File:** `internal/crossview/crossview.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** The `processes` map grows monotonically — processes are added on fork/exec but never removed. Dead processes (`Alive = false`) remain in the map forever. On a long-running system with process churn (e.g., a build server, CI/CD pipeline), this map grows without bound. Similarly, `conns` grows without bound. The `reconcileProcesses()` function iterates over ALL processes (including dead ones) on every reconciliation cycle.
- **Impact:** OOM kill of VIGIL on systems with high process churn. Degraded reconciliation performance as the map grows. False positives as dead processes accumulate and /proc entries disappear (they'd appear "hidden").
- **Fix:** Implement a periodic cleanup sweep that removes processes dead for > 5 minutes. Alternatively, use a TTL-based eviction. Cap the map size as a TCA defense. Also skip dead processes early in `reconcileProcesses()` (the code does check `!proc.Alive` and `continue`, but still iterates over them).

### BUG-012: Unbounded Process Tracking in Lineage
- **File:** `internal/lineage/lineage.go`
- **Category:** Resource Leak
- **Severity:** CRITICAL
- **Description:** Same as BUG-011. The `tree` map grows monotonically. Dead processes are never pruned. `seedFromProc()` adds all processes at startup, and eBPF events keep adding more. The `applyRules()` function iterates over the entire tree every 30 seconds.
- **Impact:** Same as BUG-011 — OOM, degraded performance, false positives.
- **Fix:** Implement periodic pruning of dead processes. Add a `reaper()` goroutine that removes nodes where `!Alive && time.Since(ExitNS) > 10*time.Minute`.

---

## HIGH Findings

### BUG-013: Cross-View Event Type Constant Mismatch with models.go
- **File:** `internal/crossview/crossview.go` vs `internal/models/models.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** `crossview.go` defines its own `CVEvent*` constants (lines 42-46) that duplicate the ones in `models.go` (lines 113-117). While the values currently match, this is a maintenance hazard — if one is updated and the other isn't, events will be silently misinterpreted. The same applies to `CVEventTypeNames` which is duplicated. Similarly, `TCPStateNames` is defined in crossview.go but not in models.go — if another module needs TCP state names, they'd have to duplicate them.
- **Impact:** Future constant changes will cause silent event misinterpretation. Events could be dispatched to the wrong handler or logged with wrong names.
- **Fix:** Remove the duplicate constants from `crossview.go` and use `models.CVEvent*` exclusively. Move `TCPStateNames` to `models.go` if shared.

### BUG-014: handleTCPState Does Not Track Connections
- **File:** `internal/crossview/crossview.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** `handleTCPState()` logs TCP state changes and updates `stats.KernelConns` to `len(cvc.conns)`, but it never actually adds connections to the `conns` map. The `conns` map is always empty, so `reconcileConnections()` never finds any kernel-side connections, making the entire connection reconciliation a no-op. Every eBPF-tracked connection is invisible to the reconciliation logic.
- **Impact:** Hidden connections (rootkit hiding TCP connections from /proc/net/tcp) are never detected. The connection cross-view check is completely non-functional.
- **Fix:** In `handleTCPState()`, create a `ConnectionInfo` from the parsed event and store it in `cvc.conns` keyed by socket address or connKey. Remove the entry when the state reaches TCPClose/TCPTimeWait.

### BUG-015: parseForkEvent Size Check Mismatch
- **File:** `internal/crossview/crossview.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** `parseForkEvent()` checks `len(raw) < 52` but the comment says the layout is 56 bytes (event_type(4) + pid(4) + ppid(4) + pad(4) + timestamp(8) + parent_comm(16) + child_comm(16)). The code reads up to offset 56 (`raw[40:56]`), so the bounds check should be `< 56`. With the current check of `< 52`, if raw is exactly 52-55 bytes, the function will successfully parse but `raw[40:56]` will panic with an index out of range.
- **Impact:** Panic (crash of VIGIL) on malformed/truncated ringbuf events.
- **Fix:** Change `len(raw) < 52` to `len(raw) < 56`.

### BUG-016: parseRenameEvent Offset Mismatch
- **File:** `internal/crossview/crossview.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** The comment says the rename event layout is: `event_type(4) + pid(4) + _pad(4) + timestamp(8) + oldcomm(16) + newcomm(16) = 52 bytes`. But the code reads `timestamp = binary.LittleEndian.Uint64(raw[12:20])` and `oldComm = raw[20:36]`, `newComm = raw[36:52]`. If the layout truly has 4 bytes of padding after pid (at offset 8), then the timestamp starts at offset 12, which matches. However, the bounds check is `< 52` and the function reads up to `raw[36:52]`, so this is actually correct — but only if the eBPF C struct truly has 4 bytes of padding. The comment says `_pad(4)` which is unusual — most eBPF structs pack tightly or use explicit alignment. If the C struct has no padding, the timestamp would be at offset 8, and all subsequent fields would be shifted by 4 bytes.
- **Impact:** If the C struct has no padding (which is the more common pattern), all rename event fields after PID would be misinterpreted — wrong timestamp, wrong comm names.
- **Fix:** Verify against the actual eBPF C struct definition. Use `binary.Read()` with an explicit struct to avoid offset arithmetic errors. Consider using `unsafe.Sizeof` verification in the eBPF C code.

### BUG-017: syscallarg Rule Matching Operator Precedence Bug
- **File:** `internal/syscallarg/syscallarg.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** In the `matches()` method, the path pattern check has incorrect operator precedence:
  ```go
  if r.PathPattern != "" && event.EventType == models.ArgEventOpen || event.EventType == models.ArgEventExecve {
  ```
  This evaluates as `(r.PathPattern != "" && event.EventType == models.ArgEventOpen) || event.EventType == models.ArgEventExecve` due to Go's operator precedence (`&&` binds tighter than `||`). This means for ANY execve event, the path pattern check is bypassed — the condition is always true for execve events regardless of whether `PathPattern` is set. The `filepath.Match` call will then be called with an empty pattern, which returns `true` for any path. As a result, rules with `EventType: "execve"` that don't set a `PathPattern` will match ALL execve events, and rules with `EventType: "execve"` that DO set a `PathPattern` will also match ALL execve events (ignoring the pattern).
  
  Additionally, if a rule has no `EventType` set (`r.EventType == ""`), the event type check is skipped, and then the path check applies to ALL event types — including connect and capable events where `Path` may contain garbage data.
- **Impact:** (1) Over-alerting: every execve event triggers every execve-type rule, causing alert flooding. (2) Rules meant to match specific paths on execve (e.g., `*/bash` from web servers) match ALL execve events. (3) Rules with no EventType but with PathPattern match against all event types.
- **Fix:** Add parentheses: `if r.PathPattern != "" && (event.EventType == models.ArgEventOpen || event.EventType == models.ArgEventExecve) {`. Also check `r.EventType == ""` before applying event-type-specific logic.

### BUG-018: Allow-All-UID-0-Caps Rule Defeats All Capability Monitoring
- **File:** `internal/syscallarg/syscallarg.go`
- **Category:** Security
- **Severity:** HIGH
- **Description:** The default rule `allow-systemd-uid0-caps` allows ALL capability checks by UID 0 (root). Since most kernel capability checks are performed by root processes (daemons running as root, sudo, etc.), this rule suppresses virtually all capability alerts. The rule comes before the specific capability alert rules (`cap-sys-admin`, `cap-net-admin`, `cap-sys-ptrace`, `cap-sys-rawio`), and since first-match wins, none of the alert rules ever fire for root processes. This effectively disables capability monitoring for the most security-critical user (root).
- **Impact:** All CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE, and CAP_SYS_RAWIO usage by root processes is silently allowed. An attacker who achieves root can use any capability without triggering alerts.
- **Fix:** Remove the blanket `allow-systemd-uid0-caps` rule. Instead, add specific allowlist rules for known legitimate root processes (systemd, dbus-daemon, etc.) by comm name. Or change the rule matching to not be first-match-wins but instead to evaluate all rules and alert if any deny/alert rule matches unless an explicit allowlist rule for that specific process+capability combination exists.

### BUG-019: Detector Mutex Held During Long Statistical Computation
- **File:** `internal/detector/detector.go`
- **Category:** Race Condition
- **Severity:** HIGH
- **Description:** The `detect()` method holds `d.mu.Lock()` for its entire duration, including: iterating all windows, calling `window.snapshot()`, running the KS test (which sorts and iterates up to 10,000+10,000 samples), running Welch's t-test, and generating alerts. With 6+ functions each having 10,000-sample windows, this can take hundreds of milliseconds. During this time, `addEvent()` is blocked, causing the event channel to fill up and events to be dropped (the backpressure mechanism in `readEvents()`). This means timing events are lost during detection cycles, creating gaps in the sliding window that could cause false negatives (missing real anomalies) or false positives (artificially lower window means).
- **Impact:** Event loss during detection cycles degrades detection accuracy. Under high event rates, the detection loop can starve the event reader.
- **Fix:** Release the lock after taking the snapshot. Copy the window snapshots under lock, then release the lock and run the statistical tests on the copies. This allows events to continue flowing while detection runs.

### BUG-020: KS Test O(n²) Complexity — DoS Vector
- **File:** `internal/baseline/baseline.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** The `KSTest()` function iterates over ALL unique values in both samples (`allVals` can be up to 20,000 elements). For each value, it calls `empiricalCDF()` which does a linear scan over the baseline (up to 10,000 elements) and window (up to 10,000 elements). Total complexity is O((n+m) * (n+m)) = O(400M) for 10K+10K samples. Since `detect()` holds the mutex during this (BUG-019), this amplifies the event-starvation problem. Furthermore, `empiricalCDF()` uses `break` on the first value > x, which only works if the input is sorted — but `baseline` passed to KSTest may not be sorted (it's the raw `bl.Samples` from `GetAllBaselines()`, which IS sorted by `computeBaselines()`, but this is an implicit assumption, not enforced).
- **Impact:** Detection cycle takes O(400M) operations per function per cycle. With 6 functions, that's 2.4 billion operations — potentially seconds of CPU time. This is a DoS vector: an attacker who can influence timing samples (e.g., by causing I/O stalls that create many unique values) can slow VIGIL's detection to a crawl.
- **Fix:** Use binary search for CDF computation (pre-sort both arrays and use `sort.Search`). Or use the standard KS test algorithm that merges two sorted arrays in O(n+m) and computes CDFs in a single pass. Also explicitly sort the inputs at the start of KSTest to remove the implicit assumption.

### BUG-021: KS Test One-Sided Direction May Miss Rootkit Hooks
- **File:** `internal/baseline/baseline.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** The KS test is one-sided: it only looks at `cdf1 - cdf2` (baseline CDF minus window CDF), reasoning that a right shift (slower window) means the window CDF is below the baseline CDF. However, for a right shift, at the RIGHT tail, the window CDF reaches 1 slower than the baseline CDF — so `cdf1 - cdf2` IS positive there. But at the LEFT tail, `cdf1 - cdf2` is also positive (baseline CDF rises faster). The maximum D+ could actually occur at the LEFT tail for a right shift, which is fine. The real issue is: if a rootkit hook adds a CONSTANT delay (e.g., 500μs) to every call, the window distribution is the baseline distribution shifted right by 500μs. The KS D statistic for this case would be very large (close to 1.0 for well-separated distributions). But if the rootkit hook adds a VARIABLE delay (sometimes 0, sometimes 500μs), the window distribution is a mixture. In this case, the one-sided test only captures the portion where the CDFs differ maximally in one direction. This might miss cases where the mixture creates CDF crossings.
  
  More critically, the test uses `maxD` which is the maximum of `cdf1 - cdf2` only (D+). It never considers `cdf2 - cdf1` (D-). If a rootkit REMOVES latency (e.g., by short-circuiting a security check), the window would shift LEFT, and D- would be large while D+ is near zero. This attack is mentioned in academic literature (rootkits that optimize kernel paths to hide their own activity).
- **Impact:** Rootkits that reduce kernel function execution time (e.g., by skipping security checks) are never detected by the KS test. The one-sided test only catches slowdowns, not speedups.
- **Fix:** Consider using the two-sided KS test (max of D+ and D-) with a higher threshold, or run both one-sided tests and alert on either. Document the tradeoff: two-sided increases false positives from legitimate optimizations (caching, etc.).

### BUG-022: tCriticalValue Approximation Is Incorrect
- **File:** `internal/baseline/baseline.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** The `tCriticalValue()` function uses rough linear interpolation for small degrees of freedom. The formula `return 2.821 + (3.250-2.821)*(df-5)/5` for `df < 10` interpolates between t-values for df=5 and df=10, but the actual t-distribution is not linear. For df=1, the one-sided t-critical at α=0.01 is 31.82, but the formula gives `2.821 + (3.250-2.821)*(1-5)/5 = 2.821 - 0.343 = 2.478`, which is wildly wrong. For df=2, the actual value is 6.96, but the formula gives ~2.578. This means for small sample sizes (which can happen after outlier filtering removes samples), the t-test uses a critical value that is far too low, causing massive false positives.
- **Impact:** With small effective sample sizes (after outlier filtering), the t-test threshold is far too permissive, causing false positive alerts. An attacker could inject outliers to force the outlier-filtering fallback (which keeps all samples but may reduce below minimum thresholds), triggering false alerts.
- **Fix:** Use a proper t-distribution implementation. The `gonum.org/v1/gonum/stat/distuv` package provides `StudentT{}.Quantile()`. Alternatively, use a comprehensive lookup table with proper interpolation (e.g., using the inverse incomplete beta function approximation).

### BUG-023: Baseline Refresh Goroutine Leak
- **File:** `internal/baseline/baseline.go`
- **Category:** Resource Leak
- **Severity:** HIGH
- **Description:** In `RefreshPeriodically()`, each refresh cycle starts a new goroutine to read events (`go func() { ... }()`). This goroutine reads from `mgr.ReadEvent()` and sends to `sampleCh`. The goroutine exits when either `ctx.Done()` or the `sampleCh` is closed. However, `sampleCh` is never closed — the refresh loop simply `break collect` when the deadline hits, leaving `sampleCh` open. The goroutine continues running, blocked on `sampleCh <- event` forever (or until ctx is cancelled). Over multiple refresh cycles, goroutines accumulate: one per refresh cycle (every few hours).
- **Impact:** Goroutine leak — one per refresh cycle. Each goroutine holds a stack and prevents GC of captured variables. Over weeks of operation, dozens of leaked goroutines accumulate.
- **Fix:** Close `sampleCh` after the `collect` loop exits. The goroutine will unblock when the channel is closed (or use `select` with a done channel). Alternatively, restructure so the reader goroutine is started once and signaled to stop reading.

### BUG-024: Baseline Learn Phase Goroutine Leak on Done
- **File:** `internal/baseline/baseline.go`
- **Category:** Resource Leak
- **Severity:** HIGH
- **Description:** In `Learn()`, the event reader goroutine (`go func() { defer close(done); ... }()`) reads events from `mgr.ReadEvent()` and sends to `sampleCh`. When the learning phase completes (deadline or context cancelled), the main `Learn()` function returns without stopping the reader goroutine. The goroutine continues calling `mgr.ReadEvent()` in a tight loop (the `default` branch in the inner select means it spins on errors). The `done` channel is closed when the goroutine exits, but the goroutine never exits because `mgr.ReadEvent()` keeps returning events or errors.
- **Impact:** Goroutine leak after each learn phase. If learn is restarted (e.g., baseline reset), goroutines accumulate.
- **Fix:** Pass `ctx` to the reader goroutine and have it check `ctx.Done()` before each `ReadEvent()` call. Close `sampleCh` to unblock the sender.

### BUG-025: No Rate Limiting on Alert Generation
- **File:** `internal/ttyguard/ttyguard.go` (and others)
- **Category:** Security
- **Severity:** HIGH
- **Description:** `handleTTYRead()` generates a WARN alert for EVERY TTY read event from non-daemon processes. There is no rate limiting — if a process reads TTY input continuously (e.g., a legitimate terminal emulator like `bash` reading from stdin), VIGIL generates one alert per read event, which could be thousands per second. The same pattern exists in `dnsguard` (alert per DNS query), `flowguard` (alert per suspicious port connection), `lineage` (alert per ptrace event), and `crossview` (alert per hidden process per reconciliation cycle). An attacker could deliberately trigger high-volume events to flood the alert system, causing log exhaustion, alert fatigue, and potentially crashing VIGIL.
- **Impact:** Alert flooding causes: (1) log storage exhaustion, (2) alert fatigue in operators, (3) CPU/memory pressure from alert processing, (4) potential DoS of VIGIL itself.
- **Fix:** Implement per-process rate limiting in the alert manager. Use token bucket or sliding window rate limiting: e.g., max 1 alert per (pid, category) per 60 seconds. Aggregate similar alerts and report counts. Add a per-category alert budget.

### BUG-026: handleCredChange Parses comm at Wrong Offset
- **File:** `internal/lineage/lineage.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** `handleCredChange()` reads `comm := string(raw[40:56])` but the event layout (based on the parsing code) appears to be: event_type(4) + pid(4) + oldUID(4) + newUID(4) + oldGID(4) + newGID(4) + ??? + comm(16). The fields parsed are: pid at [4:8], oldUID at [8:12], newUID at [12:16], oldGID at [16:20], newGID at [20:24]. That's 24 bytes of data + 4 for event type = 28 bytes. Then comm is read at [40:56]. What's at [24:40]? That's 16 bytes of unaccounted space. If there's padding or additional fields there, the comm offset might be correct, but if the struct is packed, comm should be at [24:40]. The bounds check is `< 52` but `raw[40:56]` needs 56 bytes.
- **Impact:** Comm field is read from the wrong offset, producing garbage process names. Alerts contain incorrect process names, misleading responders. If the comm is actually at [24:40], the correct comm is replaced by whatever data is at [40:56] (possibly padding or a path field).
- **Fix:** Verify against the eBPF C struct. Use `binary.Read()` with an explicit struct definition to avoid offset errors. Fix the bounds check to `< 56` if the offset is correct.

### BUG-027: handlePtrace Bounds Check Too Permissive
- **File:** `internal/lineage/lineage.go`
- **Category:** Logic Error
- **Severity:** HIGH
- **Description:** `handlePtrace()` checks `len(raw) < 56` but reads `raw[40:56]` for `targetComm`. The fields are: event_type(4) + sourcePID(4) + targetPID(4) + request(4) + ??? + sourceComm(24:40) + targetComm(40:56). What's at [12:24]? That's 12 bytes. If request is at [12:16], then [16:24] is 8 bytes unaccounted. The function reads `sourceComm = raw[24:40]` and `targetComm = raw[40:56]`, which requires 56 bytes. The bounds check of `< 56` is correct for reading `raw[40:56]`, but the gap at [16:24] needs verification.
- **Impact:** If there are no fields at [16:24], sourceComm and targetComm may be shifted, producing garbage or truncated comm names.
- **Fix:** Verify against the eBPF C struct. Use explicit struct parsing.

### BUG-028: Detector readEvents Goroutine Never Propagates Errors
- **File:** `internal/detector/detector.go`
- **Category:** Error Handling
- **Severity:** HIGH
- **Description:** The `readEvents()` goroutine silently swallows all errors from `d.mgr.ReadEvent()`. It logs nothing — just backs off for 10ms and continues. If the ringbuf is permanently closed (e.g., eBPF program detached, map removed), the goroutine spins forever in a tight loop (10ms sleep + failed read = ~100 attempts/second), consuming CPU. There's no mechanism to signal the main loop that the event source is dead.
- **Impact:** Silent detection failure. VIGIL appears to be running (no errors logged) but no events are processed. CPU wasted on failed reads.
- **Fix:** Add error classification: temporary errors (retry with backoff), permanent errors (log CRITICAL and exit the goroutine). Add a health check mechanism so the main loop can detect that the reader has failed.

### BUG-029: Cross-View Reconcile Holds Mutex During I/O
- **File:** `internal/crossview/crossview.go`
- **Category:** Race Condition
- **Severity:** HIGH
- **Description:** `reconcile()` holds `cvc.mu.Lock()` and calls `reconcileProcesses()` and `reconcileConnections()`, which both perform filesystem I/O (`os.ReadDir("/proc")`, `os.ReadFile("/proc/net/tcp")`). While the lock is held, `processEvent()` and all event handlers (`handleFork`, `handleExec`, etc.) are blocked from accessing `cvc.processes` and `cvc.conns`. Under high process creation rates, this causes the ringbuf to fill up and events to be dropped. Additionally, `reconcileProcesses()` calls `cvc.alert.Critical()` and `cvc.alert.Warn()` while holding the lock — if the alert manager blocks (e.g., on I/O or network), the lock is held longer.
- **Impact:** Event loss during reconciliation (every 60 seconds). Under high process churn, significant numbers of fork/exec/exit events are missed, creating gaps in the process tree and potential false positives (processes that were forked during reconciliation and exited before the next event is processed appear as "hidden").
- **Fix:** Copy the kernel process/connection maps under lock, then release the lock before doing I/O and alert generation. Use a snapshot approach similar to what the detector does (though detector also has the lock-during-computation problem, see BUG-019).

### BUG-030: Response Engine Stats Nil Pointer Dereference
- **File:** `internal/response/response.go`
- **Category:** Error Handling
- **Severity:** HIGH
- **Description:** In `Stats()`, when `len(e.results) == 0`, `stats.LastResponse` is nil (never initialized). The code then checks `if stats.LastResponse == nil || r.Timestamp.After(*stats.LastResponse)` — this is safe for the nil case. However, in the `else` branch (when `stats.LastResponse != nil`), `r.Timestamp.After(*stats.LastResponse)` is safe. But the real issue is when `e.results` is empty but `e.pending` is non-empty — the code doesn't check pending actions for the last response time. More critically, if `e.results` is empty, `stats.LastResponse` remains nil, and any caller that dereferences `stats.LastResponse` without a nil check will panic. The `json:"last_response,omitempty"` tag handles this for JSON, but direct Go callers might not check.
- **Impact:** Potential panic in callers of `Stats()` who dereference `LastResponse` without nil check.
- **Fix:** Document that `LastResponse` may be nil. Or return a zero-value `time.Time{}` instead of nil.

---

## MEDIUM Findings

### BUG-031: Detector Windows Map Never Cleaned Up
- **File:** `internal/detector/detector.go`
- **Category:** Resource Leak
- **Severity:** MEDIUM
- **Description:** The `windows` map in `Detector` grows per new `FuncID` seen. If the eBPF program ever sends events with unexpected FuncIDs (e.g., due to a firmware bug or eBPF program update without restart), entries are created and never removed. Each entry holds a 10,000-element `[]uint64` (80KB on 64-bit). While unlikely to be many (6 known functions), it's a latent leak.
- **Impact:** Minor memory growth in edge cases.
- **Fix:** Add a maximum function count and skip unknown FuncIDs.

### BUG-032: Detector Hits Map Not Reset on Context Cancellation
- **File:** `internal/detector/detector.go`
- **Category:** Error Handling
- **Severity:** MEDIUM
- **Description:** When `RunDetection` returns (on `ctx.Done()`), the `hits` and `windows` maps retain their state. If `RunDetection` is called again (e.g., on hot-reload), stale hit counters from a previous session could cause immediate false-positive alerts (if `hits[funcID] >= 3` was true before shutdown).
- **Impact:** False positive alerts on restart after a detection event.
- **Fix:** Reset `hits` and `windows` at the start of `RunDetection`.

### BUG-033: Baseline Save Race with ComputeBaselines
- **File:** `internal/baseline/baseline.go`
- **Category:** Race Condition
- **Severity:** MEDIUM
- **Description:** `Save()` acquires `b.mu.RLock()` while `computeBaselines()` acquires `b.mu.Lock()`. If `Save()` is called concurrently with `computeBaselines()` (e.g., from an API handler), `Save()` will block until `computeBaselines()` finishes. This is correct behavior (no data race), but `Save()` marshals the entire functions map to JSON while holding the read lock — during this time, `addSample()` is blocked. Under high event rates during baseline refresh, this causes event drops.
- **Impact:** Brief event loss during baseline save. Not critical but degrades baseline quality.
- **Fix:** Copy the baseline data under lock, release the lock, then marshal and save. Or use `json.Marshal` on a copy.

### BUG-034: Outlier Filtering Can Remove All Samples in Detector
- **File:** `internal/detector/detector.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** In `detect()`, the outlier filtering computes `cutoff := baseFn.P95 * 10.0`. If `baseFn.P95` is 0 (possible if all baseline samples are 0, e.g., for a function that returns immediately), then `cutoff` is 0, and ALL window samples are filtered out. The fallback `if len(filteredWindow) < 30` catches this, but only if fewer than 30 samples remain — if 30+ samples are 0, they pass through, and the KS test runs on all-zero arrays, which will produce D=0 and not reject. This is technically correct (no anomaly) but wastes CPU.
- **Impact:** Wasted CPU on degenerate cases. Not a correctness bug.
- **Fix:** Skip functions where `baseFn.P95 == 0` or `baseFn.Mean == 0`.

### BUG-035: Clustering Profiles Never Expire
- **File:** `internal/clustering/clustering.go`
- **Category:** Resource Leak
- **Severity:** MEDIUM
- **Description:** The `profiles` map grows per new PID. Dead processes' profiles are never removed. Over time on a system with process churn, this map grows without bound. The `evaluate()` function iterates all profiles every 30 seconds.
- **Impact:** Memory growth and degraded clustering performance over time.
- **Fix:** Add a periodic cleanup that removes profiles for PIDs no longer in `/proc`. Or add a TTL based on `LastUpdated`.

### BUG-036: Clustering Alerts Fire Every 30 Seconds for Same Process
- **File:** `internal/clustering/clustering.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** The `evaluate()` function runs every 30 seconds and applies all cluster rules to all profiles. If a profile matches a rule, an alert is fired — every 30 seconds. There's no deduplication or "already alerted" flag. A single malicious process matching a rule will generate an alert every 30 seconds until it's killed or the profile is removed.
- **Impact:** Alert flooding for persistent threats. Operators may start ignoring alerts.
- **Fix:** Track which rules have already fired for each profile. Only fire once per (profile, rule) pair. Reset when the profile's indicators change significantly.

### BUG-037: Cross-View processEvent Updates Stats Without Main Lock
- **File:** `internal/crossview/crossview.go`
- **Category:** Race Condition
- **Severity:** MEDIUM
- **Description:** `processEvent()` updates `cvc.stats` using `cvc.stats.mu` (a separate mutex within the Stats struct). This is correct for the stats fields, but `handleFork()` updates `cvc.processes` using `cvc.mu` AND `cvc.stats.KernelProcesses` using `cvc.stats.mu`. The two locks are acquired in sequence (cvc.mu, then cvc.stats.mu in handleFork; cvc.stats.mu in processEvent; cvc.mu in reconcile). This creates a lock ordering that could deadlock if any code acquires `cvc.stats.mu` before `cvc.mu`. Currently this doesn't happen, but it's fragile.
- **Impact:** Latent deadlock risk if code is added that acquires locks in different order.
- **Fix:** Document the lock ordering: always acquire `cvc.mu` before `cvc.stats.mu`. Or use a single mutex.

### BUG-038: Lineage applyRules Holds Lock During Alert Generation
- **File:** `internal/lineage/lineage.go`
- **Category:** Race Condition
- **Severity:** MEDIUM
- **Description:** `applyRules()` holds `lc.mu.Lock()` for its entire duration, including alert generation. While the lock is held, `readEvents()` and all event handlers are blocked. With a large process tree (thousands of processes), iterating all processes and matching all rules takes O(P × R) time where P = processes and R = rules. This blocks event processing.
- **Impact:** Event loss during rule evaluation (every 30 seconds).
- **Fix:** Copy the tree under lock, release the lock, then apply rules to the copy.

### BUG-039: bpfintegrity verifyBPFPrograms Counts ALL FDs as BPF Programs
- **File:** `internal/bpfintegrity/bpfintegrity.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** `verifyBPFPrograms()` reads `/proc/self/fd` and counts every entry as a "BPF program". This includes non-BPF file descriptors (socket FDs, pipe FDs, log files, etc.). The count `bpfProgs` is stored as `stats.BPFPrograms` — misleading because it's not actually BPF programs. The integrity check doesn't compare against expected program counts (`expectedProgs` map is defined but never used in `verifyBPFPrograms()`).
- **Impact:** Misleading stats. The integrity check doesn't actually verify BPF program counts. A removed BPF program would not be detected by this check.
- **Fix:** Read `/proc/self/fdinfo/[fd]` and check for `pos` or `bpf_prog_info` entries. Or use the `cilium/ebpf` library to enumerate loaded programs. Compare against `expectedProgs`.

### BUG-040: bpfintegrity handleBPFCheck Reads comm at Wrong Offset
- **File:** `internal/bpfintegrity/bpfintegrity.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** `handleBPFCheck()` checks `len(raw) < 36` but reads `comm := string(raw[28:44])` which requires 44 bytes. If raw is 36-43 bytes, this will panic with index out of range. The function reads `opcode` at `raw[16:20]` and `comm` at `raw[28:44]` — the gap [20:28] is 8 bytes, and [28:44] is 16 bytes, but the bounds check only ensures 36 bytes.
- **Impact:** Panic on truncated events.
- **Fix:** Change bounds check to `len(raw) < 44`.

### BUG-041: bpfintegrity handleProcessExit Bounds Check Mismatch
- **File:** `internal/bpfintegrity/bpfintegrity.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** `handleProcessExit()` checks `len(raw) < 28` but reads `comm := string(raw[16:32])` which requires 32 bytes. If raw is 28-31 bytes, this panics.
- **Impact:** Panic on truncated events.
- **Fix:** Change bounds check to `len(raw) < 32`.

### BUG-042: containerguard handleSetNS/handleUnshare Read comm at Wrong Offset
- **File:** `internal/containerguard/containerguard.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** `handleSetNS()` and `handleUnshare()` read `comm := string(raw[28:44])` but parse pid at [4:8], uid at [8:12], nstype at [12:16]. That's 16 bytes of data. What's at [16:28]? 12 bytes unaccounted for. The comm at [28:44] may be reading from the wrong offset. The bounds check is `< 44` which is correct for reading [28:44], but the struct layout needs verification.
- **Impact:** Garbage comm names in alerts if the offset is wrong.
- **Fix:** Verify against the eBPF C struct definition.

### BUG-043: flowguard handleConnect/handleAccept Bounds Check
- **File:** `internal/flowguard/flowguard.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** `handleConnect()` checks `len(raw) < 52` and reads `comm := string(raw[36:52])` (16 bytes). Fields parsed: pid [4:8], uid [8:12], daddr [12:16], dport [16:18]. That's 18 bytes of data. [18:36] is 18 bytes unaccounted. [36:52] is comm. The bounds check `< 52` is correct for reading [36:52], but the struct layout needs verification. Same issue in `handleAccept()`.
- **Impact:** Potentially garbage comm names.
- **Fix:** Verify against eBPF C struct.

### BUG-044: dnsguard handleQuery Reads comm at [36:52] — Verify Offset
- **File:** `internal/dnsguard/dnsguard.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** `handleQuery()` checks `len(raw) < 44` but reads `comm := string(raw[36:52])` which requires 52 bytes. If raw is 44-51 bytes, this panics. Fields: pid [4:8], dport [8:12], pktLen [12:16], daddr [20:24]. [24:36] is 12 bytes gap. comm at [36:52] needs 52 bytes but check is 44.
- **Impact:** Panic on events of 44-51 bytes.
- **Fix:** Change bounds check to `len(raw) < 52`.

### BUG-045: dnsguard procStats Map Access Not Thread-Safe
- **File:** `internal/dnsguard/dnsguard.go`
- **Category:** Race Condition
- **Severity:** MEDIUM
- **Description:** In `readEvents()`, the `procStats` map (local variable, `map[uint32]*DNSProcessStats`) is accessed only by the `readEvents()` goroutine — this is safe. However, `handleQuery()` and `handleResponse()` both access `procStats` and are called from `readEvents()`. Since they're called sequentially within the same goroutine, this is also safe. The issue is that `anomalyCheck()` accesses `dg.coll.Maps["dns_proc_stats"]` via the eBPF map iterator — this is a kernel-level map, and concurrent access from `anomalyCheck()` and eBPF programs writing to it is handled by the kernel's internal locking. So this is actually safe, but the `dg.stats` mutex is held during the entire `anomalyCheck` iteration including map iteration, which could be slow.
- **Impact:** Lock contention between `anomalyCheck` and event handlers.
- **Fix:** Copy stats under lock, release, then iterate.

### BUG-046: syscallarg FilterStats Returns Struct with Unprotected Maps
- **File:** `internal/syscallarg/syscallarg.go`
- **Category:** Race Condition
- **Severity:** MEDIUM
- **Description:** `GetStats()` acquires `saf.stats.mu.RLock()`, copies the maps, and returns. However, `FilterStats` struct contains `ByType` and `ByAction` maps. The returned struct has copied maps, but the copy is done while holding the read lock. Meanwhile, `processEvent()` acquires `saf.stats.mu.Lock()` to update these maps. This is correct (RLock vs Lock), but the `TotalEvents`, `RuleMatches`, and `AlertsFired` fields are simple int64 values that are read under the lock. This is fine for correctness but may return a slightly inconsistent snapshot (e.g., TotalEvents updated but ByType not yet).
- **Impact:** Minor inconsistency in stats reporting. Not a correctness issue.
- **Fix:** Acceptable for stats. No fix needed.

---

## LOW Findings

### BUG-047: Models FunctionID Comment Inconsistency
- **File:** `internal/models/models.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** The `FunctionID` constants list 6 functions (0-5), but `bpfintegrity.go` `expectedProgs` map says `"vigil_kprobe": 12` programs (6 kprobe pairs). This is consistent (entry + return probes), but the comment `// 6 kprobe pairs` is not verifiable from the models file alone. The `ArgEventType` constants have 4 values (1-4), but there's no `ArgEventNone = 0` for unset/invalid.
- **Impact:** Minor documentation issue.
- **Fix:** Add `ArgEventNone = 0` for completeness.

### BUG-048: Cross-View projDir Uses os.Getenv("HOME")
- **File:** `internal/crossview/crossview.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** `projDir()` checks `os.Getenv("HOME")` as a fallback for finding the project directory. In a production deployment, `HOME` may be `/root` or `/home/vigil`, and the project directory won't be there. This fallback is only useful for development.
- **Impact:** Minor — only affects development path resolution.
- **Fix:** Remove the HOME fallback or make it conditional on a debug build flag.

### BUG-049: Evidence Capture personality Typo
- **File:** `internal/response/evidence_capture.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** The `procFiles` list contains `" personality"` (with a leading space). This means the code tries to read `/proc/[pid]/ personality` (with leading space in the filename), which will always fail. The file is `/proc/[pid]/personality` (no leading space).
- **Impact:** Personality is never captured in evidence.
- **Fix:** Change `" personality"` to `"personality"`.

### BUG-050: CgroupFreezer Init Doesn't Check Freezer Availability
- **File:** `internal/response/cgroup_freezer.go`
- **Category:** Error Handling
- **Severity:** LOW
- **Description:** `Init()` checks if "freezer" appears in `cgroup.controllers` but silently ignores the result if it doesn't. The `_ = os.WriteFile(subtreeFile, ...)` on the subtree control file error is ignored. If the freezer controller is not available, `Freeze()` will fail later with a confusing error.
- **Impact:** Confusing errors at freeze time instead of clear errors at init time.
- **Fix:** Return an error from `Init()` if the freezer controller is not available. Log a warning.

### BUG-051: Network Isolator Uses PID as cgroupv2 Classid
- **File:** `internal/response/network_isolator.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** `Isolate()` constructs `cgroupMatch := fmt.Sprintf("meta cgroupv2 %d", pid)`. The `meta cgroupv2` match in nftables matches the cgroup classid, not the PID. The PID is not the cgroup classid — the cgroup classid is a separate kernel-assigned identifier. This means the nftables rule will match the wrong cgroup (or no cgroup at all), and the isolation won't work.
- **Impact:** Network isolation doesn't actually work — the nftables rule matches a cgroup classid that doesn't correspond to the target process.
- **Fix:** Look up the process's actual cgroup classid from `/proc/[pid]/cgroup` or from the cgroup path created by `CgroupFreezer.Freeze()`. Or use a different match criterion (e.g., `meta skuid` or `socket cgroupv2 level`).

### BUG-052: Evidence Capture Doesn't Capture /proc/[pid]/loginuid
- **File:** `internal/response/evidence_capture.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** The evidence capture list includes many /proc files but misses `loginuid` and `sessionid` (though sessionid IS in the list). `loginuid` is important for forensic analysis — it shows the original login UID even after `su`/`sudo`.
- **Impact:** Missing forensic evidence.
- **Fix:** Add `"loginuid"` to the `procFiles` list. Also consider adding `"automaLabel"`, `"mountinfo"`, and `"ns/*` (namespace symlinks).

### BUG-053: Baseline Random Replacement Introduces Sampling Bias
- **File:** `internal/baseline/baseline.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** In `addSample()`, when `len(bl.Samples) >= 10000`, a random index is chosen and replaced: `bl.Samples[rand.Intn(len(bl.Samples))] = elapsedNS`. This is reservoir sampling without proper replacement logic. True reservoir sampling (Algorithm R) replaces element i with probability 1/i, not uniformly at random. The current approach means early samples are equally likely to be replaced as late samples, which biases the sample toward newer data (older samples have been exposed to replacement risk for longer). This is actually desirable for a baseline that should track system changes, but it's not statistically clean reservoir sampling.
- **Impact:** Minor statistical bias in baseline samples after 10K threshold is reached. Not critical since baseline is refreshed periodically.
- **Fix:** If unbiased sampling is desired, implement Algorithm R. If tracking recent changes is desired (current behavior), document this as intentional.

### BUG-054: Percentile Calculation Uses (n-1) Index
- **File:** `internal/baseline/baseline.go`
- **Category:** Logic Error
- **Severity:** LOW
- **Description:** `percentile()` computes `idx := float64(len(sorted)-1) * p / 100.0`. This is the "exclusive" percentile method. For p=0, it returns `sorted[0]`. For p=100, it returns `sorted[len-1]`. This is a valid percentile method, but some statistical software uses `idx := float64(len(sorted)) * p / 100.0` (the "inclusive" method). The choice affects P5 and P95 values used for outlier filtering. If the eBPF C code or other components use a different percentile method, the cutoffs will be inconsistent.
- **Impact:** Minor differences in percentile values used for outlier filtering. Not critical.
- **Fix:** Document the percentile method used. Ensure consistency with any other percentile calculations in the codebase.

---

## Cross-Cutting Issues

### ISSUE-001: Universal eBPF Link Leak Pattern
Every eBPF module (lineage, bpfintegrity, dnsguard, ttyguard, containerguard, flowguard) creates `link.Kprobe()` or `link.Tracepoint()` attachments and immediately discards them with `_ = l`. The `crossview` module is the **only** one that correctly stores links in a `[]link.Link` slice and closes them in `Close()`. This is a systemic code pattern issue across 6 of 7 eBPF modules.

**Systemic Fix:** Refactor all modules to follow the `crossview` pattern: store links in a slice, close them in `Close()`.

### ISSUE-002: Universal Ringbuf Read Loop Pattern
All modules use the same `for { select { case <-ctx.Done(): return; default: } record, err := reader.Read(); ... }` pattern. This is a busy-loop when the ringbuf is empty — `reader.Read()` blocks until an event is available, so the `default` branch is only taken when no event is ready (which is rare). However, if `reader.Read()` returns errors frequently, the tight loop with `continue` can spin at 100% CPU. The `detector` module handles this with `time.Sleep(10ms)`, but other modules (lineage, bpfintegrity, dnsguard, ttyguard, containerguard, flowguard) do not.

**Systemic Fix:** Add a small backoff sleep on error in all ringbuf read loops. Or use `reader.SetDeadline()` if available.

### ISSUE-003: No Rate Limiting on Any Alert Generation
All modules generate alerts without any per-process or per-category rate limiting. The `alert.AlertManager` is called directly with `Critical()`, `Warn()`, `Info()`, and `Debug()` methods. If any detection module generates alerts at high frequency (e.g., one alert per event), the alert manager and downstream consumers (logs, dashboards, response engine) can be overwhelmed.

**Systemic Fix:** Add rate limiting to the `AlertManager` itself: per-(pid, category) token bucket, global alert budget per minute, and deduplication of identical alerts.

### ISSUE-004: Binary Parsing Without Struct Verification
All modules parse raw ringbuf bytes using `binary.LittleEndian.Uint32()` with hardcoded offsets and comments describing the C struct layout. None of the modules use `binary.Read()` with an explicit Go struct or verify that the eBPF C struct size matches the expected size. This leads to the numerous bounds check and offset errors documented above.

**Systemic Fix:** Define Go structs mirroring the eBPF C structs (with correct padding/alignment), use `binary.Read()` for parsing, and add compile-time size checks using `unsafe.Sizeof`.

---

## Models.go Constant Verification

Checked all constant blocks in `models.go` against usage in detection modules:
- `FunctionID` (0-5): Used in detector and baseline. Values are consistent.
- `DetectionCategory`: Used in alert generation across modules. Values match string constants.
- `ArgEventType` (1-4): Used in syscallarg. Values match.
- `CVEventFork/Exec/Exit/Rename/TCPState` (1-5): Defined in both `models.go` AND duplicated in `crossview.go`. Values currently match.
- `LinEventCredChange/Ptrace/SetNS/Unshare/CapCheck/SUIDExec` (1-6): Used in lineage. Values match.
- `IntEventBPFLoad/BPFFree/BPFCheck/ProcessExit` (1-4): Used in bpfintegrity. However, `IntEventBPFLoad` and `IntEventBPFFree` are defined but never handled in `bpfintegrity.go`'s `readEvents()` switch statement (only `IntEventBPFCheck` and `IntEventProcessExit` are handled). This means BPF program loads and frees are never processed.
- `DNSEventQuery/Response` (1-2): Used in dnsguard. Values match.
- `TTYEventRead/Write/PtyWrite/InputRead` (1-4): Defined in models, but `ttyguard.go` only handles `TTYEventRead`. Write, PtyWrite, and InputRead events are received but silently dropped.
- `ContEventSetNS/Unshare/NSCreate/PrivEsc/NSEscape` (1-5): Defined in models, but `containerguard.go` only handles `ContEventSetNS`, `ContEventUnshare`, and `ContEventNSEscape`. `ContEventNSCreate` and `ContEventPrivEsc` are silently dropped.
- `FlowEventConnect/Accept/TCPState/Send/Recv` (1-5): Defined in models, but `flowguard.go` only handles `FlowEventConnect` and `FlowEventAccept`. `FlowEventTCPState`, `FlowEventSend`, and `FlowEventRecv` are silently dropped.

### BUG-055: Missing Event Handlers in Multiple Modules
- **File:** `internal/bpfintegrity/bpfintegrity.go`, `internal/ttyguard/ttyguard.go`, `internal/containerguard/containerguard.go`, `internal/flowguard/flowguard.go`
- **Category:** Logic Error
- **Severity:** MEDIUM
- **Description:** Multiple modules define event type constants in `models.go` but don't handle all of them in their switch statements. This means eBPF programs may be generating events that are silently discarded. Specifically:
  - **bpfintegrity**: `IntEventBPFLoad` (1) and `IntEventBPFFree` (2) are never handled — BPF program load/free events are dropped.
  - **ttyguard**: `TTYEventWrite` (2), `TTYEventPtyWrite` (3), `TTYEventInputRead` (4) are never handled — TTY write and PTY write events are dropped.
  - **containerguard**: `ContEventNSCreate` (3) and `ContEventPrivEsc` (4) are never handled — namespace creation and privilege escalation events are dropped.
  - **flowguard**: `FlowEventTCPState` (3), `FlowEventSend` (4), `FlowEventRecv` (5) are never handled — TCP state changes and send/recv events are dropped.
- **Impact:** Significant detection blind spots. Events that the eBPF programs are designed to capture are silently discarded, leaving VIGIL blind to those attack patterns.
- **Fix:** Add handlers for all defined event types in each module. If some event types are intentionally not handled yet, add a `default:` case that logs unhandled events at debug level.

---

## Priority Remediation Order

1. **CRITICAL — Fix immediately:**
   - BUG-002 through BUG-007: eBPF link leaks (6 modules) — causes permanent kernel resource leaks
   - BUG-008: PID reuse attack — causes wrong process to be killed/frozen
   - BUG-010: Network isolator Restore is a no-op — causes permanent network isolation
   - BUG-009: Path traversal in evidence capture — security vulnerability
   - BUG-001: nftables command execution issues — security and reliability
   - BUG-011, BUG-012: Unbounded process tracking — causes OOM on long-running systems

2. **HIGH — Fix before deployment:**
   - BUG-017: syscallarg rule matching precedence — causes alert flooding
   - BUG-018: Allow-all-UID-0-caps rule — disables capability monitoring for root
   - BUG-014: Cross-view connections not tracked — detection is non-functional
   - BUG-015: parseForkEvent bounds check — causes panic
   - BUG-019: Detector mutex during computation — causes event loss
   - BUG-022: tCriticalValue approximation — causes false positives
   - BUG-025: No rate limiting — causes alert flooding
   - BUG-055: Missing event handlers — detection blind spots

3. **MEDIUM — Fix in next release:**
   - BUG-035: Clustering profiles never expire
   - BUG-036: Clustering alert flooding
   - BUG-039: bpfintegrity miscounting BPF programs
   - BUG-040, BUG-041, BUG-042, BUG-043, BUG-044: Various bounds check issues

4. **LOW — Fix when convenient:**
   - BUG-049: personality typo
   - BUG-050: CgroupFreezer init doesn't check availability
   - BUG-051: Network isolator PID vs classid mismatch
   - BUG-053, BUG-054: Statistical sampling issues

---

## Appendix: Files Audited

1. `internal/models/models.go` — Constants and shared types
2. `internal/detector/detector.go` — Statistical detection engine
3. `internal/baseline/baseline.go` — Baseline timing collection
4. `internal/crossview/crossview.go` — Cross-view integrity checker
5. `internal/lineage/lineage.go` — Process lineage tracking
6. `internal/syscallarg/syscallarg.go` — Syscall argument filtering
7. `internal/bpfintegrity/bpfintegrity.go` — eBPF self-integrity watchdog
8. `internal/dnsguard/dnsguard.go` — DNS exfiltration detection
9. `internal/ttyguard/ttyguard.go` — TTY surveillance detection
10. `internal/containerguard/containerguard.go` — Container escape detection
11. `internal/flowguard/flowguard.go` — Network flow anomaly detection
12. `internal/clustering/clustering.go` — Behavioral clustering engine
13. `internal/response/response.go` — Automated threat response
14. `internal/response/cgroup_freezer.go` — Cgroup v2 process freezer
15. `internal/response/network_isolator.go` — nftables network isolation
16. `internal/response/evidence_capture.go` — Forensic evidence capture

**Total bugs found: 55** (12 CRITICAL, 18 HIGH, 16 MEDIUM, 8 LOW, plus 1 MEDIUM cross-cutting)