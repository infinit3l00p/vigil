# VIGIL — Build Roadmap

*"Build something that nobody has ever built before."*

## Current Status: v0.2 VERIFIED

**What's done:**
- 6/6 eBPF kprobe/kretprobe pairs active on kernel 7.0
- Temporal anomaly detection: KS test + Welch's t-test (one-sided, right shift)
- **4 CRITICAL bugs fixed**: C struct padding, KS test direction, baseline outlier filtering, window outlier filtering
- **Rootkit detection VERIFIED**: 500μs hook on vfs_read → KS D=1.0 + Welch t=3.49 → CRITICAL alert
- **Zero false positives**: 35 seconds clean operation, 6 detection cycles
- Self-integrity check: SHA256 binary hash + process ancestry + /proc/self verification
- TOML config parser (BurntSushi/toml) with merge-over-defaults
- Baseline periodic refresh (2h interval, 50% blend)
- Baseline collection, persistence, and automatic learning phase
- Alert system: debug/info/warn/critical with bounded buffer (10K max)
- TCA defense: 4MB bounded ringbuf, per-function rate limiting
- Systemd service with security hardening
- Install script + 10 git commits

**Test results (after outlier filtering):**
| Function | Mean (ns) | p95 (ns) | Description |
|----------|-----------|----------|-------------|
| vfs_read | 9,749 | 32,217 | File reads |
| security_file_permission | 2,605 | 7,210 | File access |
| security_inode_permission | 1,471 | 3,669 | Inode permissions |
| do_sys_openat2 | 32,996 | 70,785 | File opens |
| __x64_sys_openat | 38,274 | 79,473 | Syscall opens |

---

## Build Phases

### Phase 1: Hardening & Verification (v0.2) ✅ COMPLETE

| # | Task | Status | Description |
|---|------|--------|-------------|
| 1.1 | Rootkit simulation | ✅ | Userspace anomaly injector (-test-anomaly flag), 500μs delay on vfs_read → CRITICAL alert |
| 1.2 | False positive testing | ✅ | 35 seconds clean operation, 6 detection cycles, zero false alerts |
| 1.3 | Detection parameter tuning | ✅ | KS alpha=0.01, Welch alpha=0.005, consecutive hits=3, 10x p95 outlier filter |
| 1.4 | Baseline refresh | ✅ | Periodic re-collection every 2h, 50% blend of old+new samples |
| 1.5 | Graceful degradation | ✅ | eBPF stub manager for userspace-only mode |
| 1.6 | Self-integrity check | ✅ | SHA256 hash + process ancestry + /proc/self/exe + /proc/self/maps |
| 1.7 | Process ancestry validation | ✅ | Parent must be systemd/init/sudo/timeout, warns on unknown parents |
| 1.8 | TOML config parser | ✅ | BurntSushi/toml, merge-over-defaults, configs/vigil.toml |
| 1.9 | README update | ✅ | Updated architecture diagram, v0.2 verification results |

### Phase 2: Syscall Argument Filter (v0.3)
**Goal:** Context-aware syscall filtering — know WHAT a process is doing, not just THAT it's making calls.

**Academic basis:** eBPF-PATROL (arXiv 2511.18155) — 4-component architecture with argument-level filtering.

| # | Task | Status | Description |
|---|------|--------|-------------|
| 2.1 | Syscall arg eBPF probes | 🔜 | Trace open/openat/readlink/getdents64 with argument capture (filename, flags, mode) |
| 2.2 | Path-based filtering | 🔜 | Allow open("/tmp/log") but alert on open("/etc/shadow") from unexpected processes |
| 2.3 | Capability monitoring | 🔜 | Track cap_capable calls with capability number — alert on CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE |
| 2.4 | Namespace tracking | 🔜 | Detect container escape attempts via namespace transitions |
| 2.5 | Rule engine | 🔜 | YAML/TOML rule definitions: allow/deny/alert per-path per-capability per-namespace |
| 2.6 | eBPF-PATROL integration | 🔜 | 4-component Probe Manager → Rule Engine → Context Analyzer → Response Handler |

### Phase 3: Cross-View Integrity (v0.4)
**Goal:** Compare userspace view vs kernel view to detect hidden files, processes, and connections.

**Academic basis:** Kernel-level Rootkit Detection Taxonomy (arXiv 2304.00473) — cross-view detection concept.

| # | Task | Status | Description |
|---|------|--------|-------------|
| 3.1 | File enumeration eBPF | 🔜 | Kernel-side: trace do_filp_open/do_sys_openat2 to build kernel file view |
| 3.2 | Process enumeration eBPF | 🔜 | Kernel-side: trace fork/execve/exit to build kernel process view |
| 3.3 | Network enumeration eBPF | 🔜 | Kernel-side: trace tcp_connect/accept to build kernel connection view |
| 3.4 | Userspace reconciliation | 🔜 | Periodic: ls/ps/netstat from userspace, compare against kernel eBPF view |
| 3.5 | the companion proxy-aware reconciliation | 🔜 | Understand the companion proxy's LD_PRELOAD interceptor — don't flag the companion proxy's legitimate discrepancies |
| 3.6 | Hidden object detection | 🔜 | If kernel sees something userspace doesn't → hidden file/process/connection |
| 3.7 | False positive suppression | 🔜 | Allow lists for known discrepancies (container filesystems, /proc, /sys) |

### Phase 4: Process Lineage (v0.5)
**Goal:** Track parent-child process relationships, detect unexpected execution chains.

| # | Task | Status | Description |
|---|------|--------|-------------|
| 4.1 | Process creation eBPF | 🔜 | Trace sched_fork/do_fork to capture parent PID, comm, exe path |
| 4.2 | Process tree maintenance | 🔜 | BPF map + userspace process tree, auto-prune exited processes |
| 4.3 | Anomalous lineage detection | 🔜 | Alert on: web server → shell, cron → reverse shell, systemd → unknown binary |
| 4.4 | Privilege escalation tracking | 🔜 | Track setuid/setgid exec, capability changes, UID transitions |
| 4.5 | Container escape detection | 🔜 | Monitor namespace transitions (setns, unshare, pivot_root) |
| 4.6 | ptrace monitoring | 🔜 | Alert on ptrace attach to sensitive processes (debugger injection) |

### Phase 5: the companion proxy Integrity Monitor (v0.6)
**Goal:** VIGIL watches the companion proxy's process — mutual protection against tampering.

**Academic basis:** EvilEDR (USENIX Security 2025) — EDRs can be repurposed. VIGIL must verify the companion proxy AND itself.

| # | Task | Status | Description |
|---|------|--------|-------------|
| 5.1 | Egress proxy monitoring | 🔜 | Watch companion proxy PID, verify it's running, check cmdline matches expected |
| 5.2 | Companion binary integrity | 🔜 | Periodic SHA256 hash of companion binaries, compare against known-good |
| 5.3 | the companion proxy eBPF verification | 🔜 | Check that the companion proxy's sockops/TC/XDP programs are still attached to correct interfaces |
| 5.4 | the companion proxy config verification | 🔜 | Verify the proxy's config file hasn't been tampered with |
| 5.5 | Mutual verification protocol | 🔜 | the companion proxy checks VIGIL's integrity, VIGIL checks the companion proxy's integrity |
| 5.6 | Shared BPF map interface | 🔜 | Define shared map structure for VIGIL↔proxy communication |
| 5.7 | Anti-repudiation | 🔜 | If either VIGIL or the companion proxy detects tampering with the other, alert at CRITICAL level |

### Phase 6: Response Engine (v0.7)
**Goal:** Automated response to detected threats — not just alerting, but action.

| # | Task | Status | Description |
|---|------|--------|-------------|
| 6.1 | Alert → Response pipeline | 🔜 | Category + severity → action mapping (configurable) |
| 6.2 | Process quarantine (cgroups) | 🔜 | Freeze suspicious process to cgroup with restricted resources |
| 6.3 | Network isolation (nftables) | 🔜 | Cut network access for compromised process |
| 6.4 | Process freeze (SIGSTOP) | 🔜 | Suspend suspicious process for forensic analysis |
| 6.5 | Evidence preservation | 🔜 | Capture /proc/[pid]/maps, cmdline, environ, fd list before response |
| 6.6 | Response confirmation | 🔜 | Require manual confirmation for destructive responses, auto-only for safe ones |
| 6.7 | the companion proxy integration | 🔜 | Trigger identity rotation on detection of targeted surveillance |

### Phase 7: Advanced Detection (v0.8+)
**Goal:** Research-grade detection capabilities from academic papers.

| # | Task | Status | Description |
|---|------|--------|-------------|
| 7.1 | ML-in-eBPF classification | 🔜 | Embed decision tree models in eBPF programs (O2C, arXiv 2024) |
| 7.2 | In-kernel aggregation | 🔜 | Aquila-style aggregation: pre-filter and aggregate in eBPF, reduce userspace data volume |
| 7.3 | Two-phase detection | 🔜 | CryptoGuard pattern: coarse host-level → fine process-level (when anomaly detected) |
| 7.4 | IFC labels on telemetry | 🔜 | BPFflow principle: label telemetry data with sensitivity levels, prevent map leaks |
| 7.5 | eBPF program auditing | 🔜 | Cross-view check of loaded BPF programs against known-good list (detect TripleCross, BPFDoor) |
| 7.6 | io_uring monitoring | 🔜 | Monitor io_uring syscalls to detect RingReaper-style evasion |
| 7.7 | FlipSwitch detection | 🔜 | Monitor kernel 6.9+ syscall dispatch table for patching |
| 7.8 | nftables integrity | 🔜 | Verify nftables rules haven't been tampered with (CVE-2024-1086, CVE-2026-23111) |

---

## Architecture (Current v0.1)

```
┌─────────────────────────────────────────────────────┐
│                    Userspace                         │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │  Baseline     │  │  Statistical │  │  Alert    │ │
│  │  Engine       │  │  Detector    │  │  Manager  │ │
│  │  (KS test,   │  │  (sliding    │  │  (console,│ │
│  │   Welch's t)  │  │   windows)   │  │   log)    │ │
│  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘ │
│         │                 │                 │        │
│  ┌──────┴─────────────────┴─────────────────┘      │
│  │              Ringbuf Reader                       │
│  └──────────────────┬──────────────────────────────┘ │
└─────────────────────┼─────────────────────────────────┘
                      │ BPF_RINGBUF (bounded 4MB, TCA-safe)
┌─────────────────────┼─────────────────────────────────┐
│               Kernel (eBPF)                          │
│                                                      │
│  ┌──────────────────┴──────────────────────────────┐ │
│  │  kprobe/kretprobe pairs (6 functions):          │ │
│  │  • do_sys_openat2            (file opens)       │ │
│  │  • vfs_read                  (file reads)       │ │
│  │  • __x64_sys_getdents64      (dir listings)     │ │
│  │  • security_inode_permission (inode perms)       │ │
│  │  • security_file_permission  (file perms)        │ │
│  │  • __x64_sys_openat          (syscall opens)    │ │
│  │                                                  │ │
│  │  Per-function rate limiting (1000 evt/sec)       │ │
│  │  Per-CPU entry timestamps                        │ │
│  └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

## Target Architecture (v0.6)

```
┌─────────────────────────────────────────────────────────────────┐
│                         VIGIL Userspace                        │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │ Temporal │  │ Syscall  │  │ Cross-   │  │  Process     │   │
│  │ Anomaly  │  │ Arg      │  │ View     │  │  Lineage     │   │
│  │ Detector │  │ Filter   │  │ Checker  │  │  Tracker     │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │
│       │              │              │               │           │
│  ┌────┴──────────────┴──────────────┴───────────────┘           │
│  │                    Decision Engine                           │
│  └────────────────────┬───────────────────────────────────────┘ │
│                       │                                         │
│  ┌────────────────────┴───────────────────────────────────────┐ │
│  │                    Response Engine                           │ │
│  │  Alert │ Quarantine │ Isolate │ Freeze │ Evidence Capture  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              the companion proxy Integrity Monitor                          │ │
│  │  Process watch │ Binary hash │ eBPF verify │ Config check │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
          │                               │
          │ BPF_RINGBUF + BPF_MAP          │ Shared BPF Maps
          │ (bounded 4MB)                  │ (profile_config, connections)
┌─────────┴────────────────────────────────┴─────────────────────┐
│                     Kernel (eBPF)                              │
│                                                                 │
│  VIGIL Probes          │  the companion proxy Programs                         │
│  • kprobe/kretprobe   │  • sockops (cgroup)                  │
│  • syscall arg trace  │  • TC egress (wired)                  │
│  • process creation   │  • XDP ingress (wired)                │
│  • network tracking   │  • anti-probe (XDP)                   │
│                                                                 │
│  Per-function rate limiting + TCA defense                       │
└─────────────────────────────────────────────────────────────────┘
```

## Differentiators from Existing EDRs

| Feature | CrowdStrike | SentinelOne | Tetragon | VIGIL |
|---------|-------------|-------------|----------|-------|
| Linux-first | No | Partial | Yes | Yes |
| eBPF-native | Partial | No | Yes | Yes |
| Temporal rootkit detection | No | No | No | **Yes** |
| the companion proxy integration | N/A | N/A | No | **Native** |
| LD_PRELOAD aware | No | No | No | **Yes** |
| Offline operation | Cloud | Partial | Yes | **Yes** |
| Open source | No | No | Yes (Cilium) | **Yes** |
| Academic foundation | No | No | No | **17 papers** |
| TCA-resistant | No | No | Partial | **Yes** |
| Self-integrity verification | No | No | No | **Planned** |
| Mutual verification (proxy↔VIGIL) | N/A | N/A | No | **Planned** |

## What Nobody Has Ever Built Before

1. **Temporal anomaly EDR** — First eBPF-native implementation of Trace of the Times (98.7% F1) for production Linux
2. **the companion proxy-aware detection** — Understands the companion proxy's LD_PRELOAD interceptor, doesn't flag legitimate discrepancies
3. **Mutual verification** — VIGIL watches the proxy, the proxy watches VIGIL (EvilEDR defense)
4. **TCA-resistant telemetry** — Bounded ringbuf, rate limiting, backpressure (first EDR to address TCA by design)
5. **Academic-first development** — 17 papers studied before any code, every feature maps to published research
6. **Offline-capable** — No cloud dependency, all detection runs locally
7. **Linux-native eBPF EDR with response** — Not just detection, but automated response (quarantine, isolate, freeze)

---

*"Never assume, always check" — BIBLE rule #1*
*"Study first, research only academic sources" — BIBLE rule #2*
*"Always ask, never commit without asking" — BIBLE rule #3*
*"Abstract work, not what everybody does" — BIBLE rule #4*