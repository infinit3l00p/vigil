# VIGIL EDR Full Security Audit — v0.5.1

**Date:** 2026-06-24  
**Auditors:** 3 parallel subagents + manual review  
**Scope:** All 23 Go files (~8,644 lines) + 9 eBPF C source files (~3,200 lines)  

## Summary

| Severity | Count | Fixed |
|----------|-------|-------|
| CRITICAL | 12 | 12 ✅ |
| HIGH | 18 | 10 ✅ |
| MEDIUM | 16 | 5 ✅ |
| LOW | 8 | 2 ✅ |
| **Total** | **54+** | **29** |

## CRITICAL Fixes Applied

### BUG-002 through BUG-007: eBPF Link Leaks (6 modules) ✅
- **Files:** lineage.go, bpfintegrity.go, dnsguard.go, ttyguard.go, containerguard.go, flowguard.go
- **Issue:** All 6 modules created `link.Kprobe()`/`link.Tracepoint()` attachments and discarded them with `_ = l`, causing permanent kernel BPF attachment leaks
- **Fix:** Added `links []link.Link` field to each struct, store links, close them in `Close()`

### BUG-008: PID Reuse Attack in Response Engine ✅
- **File:** response.go
- **Issue:** TOCTOU between PID check and action execution — process could exit, PID recycled, wrong process killed/frozen
- **Fix:** Added `verifyPID()` function that checks `/proc/[pid]/stat` starttime against alert timestamp

### BUG-009: Path Traversal in Evidence Capture ✅
- **File:** evidence_capture.go
- **Issue:** Unsanitized `attackType` string in filepath construction
- **Fix:** Sanitize path-unsafe characters, verify result within evidenceDir

### BUG-010: Network Isolator Restore No-Op ✅
- **File:** network_isolator.go
- **Issue:** `Restore()` only listed nftables chain, never deleted rules — permanent isolation
- **Fix:** Parse `nft -a list chain` output, find rule handle by comment, delete by handle

### BUG-011: Unbounded Process Tracking in CrossView ✅
- **File:** crossview.go
- **Issue:** `processes` map grows monotonically, dead processes never removed → OOM
- **Fix:** Added `pruneDeadProcesses()` running every 5 minutes, removes processes dead >10 min

### BUG-012: Unbounded Process Tracking in Lineage ✅
- **File:** lineage.go
- **Issue:** Same as BUG-011 — `tree` map grows without bound
- **Fix:** Added `pruneDeadProcesses()` to rule engine loop, every 5 min

### BUG-014: CrossView Connections Never Tracked ✅
- **File:** crossview.go
- **Issue:** `handleTCPState()` updated stats but never added connections to `conns` map — connection reconciliation non-functional
- **Fix:** Track ESTABLISHED/LISTEN connections, remove on CLOSE/TIME_WAIT, changed map key to string

## HIGH Fixes Applied

### BUG-017: syscallarg Rule Precedence Bug ✅
- **File:** syscallarg.go
- **Issue:** `&&` binds tighter than `||` — ALL execve events matched ALL execve rules regardless of PathPattern
- **Fix:** Added parentheses: `r.PathPattern != "" && (event.EventType == Open || event.EventType == Execve)`

### BUG-018: Allow-All-UID-0-Caps Rule ✅
- **File:** syscallarg.go
- **Issue:** Blanket allow for ALL UID 0 capability checks suppressed all root capability alerts
- **Fix:** Split into specific comm-based rules (systemd, dbus-daemon)

### BUG-015: parseForkEvent Bounds Check ✅
- **File:** crossview.go
- **Issue:** Check `< 52` but reads up to `raw[40:56]` (needs 56) — panic on truncated events
- **Fix:** Changed to `< 56`

### BUG-040: bpfintegrity handleBPFCheck Bounds Check ✅
- **File:** bpfintegrity.go
- **Issue:** Check `< 36` but reads `comm` at `[28:44]` (needs 44) — panic
- **Fix:** Changed to `< 44`

### BUG-041: bpfintegrity handleProcessExit Bounds Check ✅
- **File:** bpfintegrity.go
- **Issue:** Check `< 28` but reads `comm` at `[16:32]` (needs 32) — panic
- **Fix:** Changed to `< 32`

### BUG-044: dnsguard handleQuery Bounds Check ✅
- **File:** dnsguard.go
- **Issue:** Check `< 44` but reads `comm` at `[36:52]` (needs 52) — panic
- **Fix:** Changed to `< 52`

### BUG-055: Missing Event Handlers (4 modules) ✅
- **Files:** ttyguard.go, containerguard.go, flowguard.go, bpfintegrity.go
- **Issue:** 55 event types defined in models.go but silently dropped — detection blind spots
- **Fix:** Added handlers for TTYEventWrite, TTYEventPtyWrite, TTYEventInputRead, ContEventNSCreate, ContEventPrivEsc, FlowEventTCPState, FlowEventSend, FlowEventRecv, IntEventBPFLoad, IntEventBPFFree

## eBPF C Kernel Fixes

### bpf_probe_read_kernel → bpf_probe_read_user (vigil_dns.c) ✅
- **Issue:** DNS sendto/recvfrom hooks read user-space `sockaddr_in` with `bpf_probe_read_kernel` — wrong address space, returns garbage or fails
- **Fix:** Changed all 6 occurrences to `bpf_probe_read_user`

### CrossView exec scratch buffer overwrite ✅
- **Issue:** In `handle_sched_process_exec`, path was read into scratch buffer, then zeroed before being copied to new process record — exec path lost for pre-existing processes
- **Fix:** Removed erroneous `__builtin_memset(scratch->path, 0, ...)` in else branch

### Dead code removal ✅
- **Issue:** `read_data_loc_str()` function in vigil_crossview.c was defined but did nothing (returned 0)
- **Fix:** Removed entirely

## LOW Fixes Applied

### BUG-049: Evidence Capture personality typo ✅
- **File:** evidence_capture.go
- **Issue:** `" personality"` with leading space — file never captured
- **Fix:** Changed to `"personality"`

## Known Limitations (Documented, Not Fixed)

### kprobe per-CPU map key reuse (vigil_kprobe.c)
- `entry_timestamps` keyed by `func_id` only — concurrent threads on same CPU overwrite each other's timestamps
- Causes timing inaccuracies under high concurrency but doesn't crash
- Fix requires architectural change to LRU_HASH with pid_tgid key — deferred to v0.6

### Dashboard auth (not yet fixed)
- No authentication on API endpoints — binds to all interfaces
- Fix requires config option for bind address + auth token — deferred to dashboard rewrite

### Detector mutex during computation (BUG-019)
- KS test holds mutex for entire detection cycle — events blocked
- Fix requires snapshot-then-release pattern — deferred to v0.6

### tCriticalValue approximation (BUG-022)
- Rough linear interpolation wildly wrong for small sample sizes
- Fix requires proper t-distribution implementation — deferred to v0.6

### Alert rate limiting (BUG-025)
- No per-process or per-category rate limiting on alert generation
- Fix requires AlertManager-level token bucket — deferred to v0.6

## Build Status

```
go build ./... — PASS (clean, no errors)
```