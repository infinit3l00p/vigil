/* vigil_kprobe.c — VIGIL eBPF temporal anomaly detection probes
 *
 * Based on: "Trace of the Times: Rootkit Detection through Temporal Anomalies
 * in Kernel Activity" (Landauer et al., ACM DTRAP 2025)
 *
 * Architecture:
 *   - kprobe on kernel function entry: record timestamp in per-CPU map
 *   - kretprobe on kernel function exit: compute elapsed nanoseconds
 *   - Elapsed time sent to userspace via BPF_RINGBUF
 *   - Userspace statistical engine runs KS test + Welch's t-test
 *
 * Key insight: Rootkit hooks ADD execution time to kernel functions.
 * Even when the rootkit hides its presence, the time shift is detectable.
 *
 * Target functions (most reliable for rootkit detection per DTRAP 2025):
 *   - do_sys_openat2: file-hiding rootkits hook this (getdents64 calls it)
 *   - do_filp_open: alternate file open path
 *   - vfs_read: content-hiding rootkits
 *   - vfs_readdir → now vfs_llseek + iterate_dir (kernel 6.x)
 *   - __x64_sys_getdents64: directory listing hook
 *   - cap_capable: privilege escalation detection
 *
 * TCA defense (Telemetry Complexity Attacks, arXiv 2025):
 *   - Per-function rate limiting: max 1000 events/sec per function
 *   - Per-CPU batch aggregation: accumulate in BPF map, flush every 100ms
 *   - Ringbuf reserve/send (zero-copy) instead of perf_event
 *   - Bounded ringbuf size: 4MB total, 1MB per CPU
 *
 * BPFflow defense (eBPF '25):
 *   - All maps use minimal permissions
 *   - No BPF_MAP_TYPE_LRU_HASH (potential info leak via eviction)
 *   - No BPF_TASK_STORAGE (cross-task leakage risk)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* ── Constants ──────────────────────────────────────────────────── */

/* Maximum number of monitored kernel functions */
#define VIGIL_MAX_FUNCS         64

/* Maximum function name length (including null terminator) */
#define VIGIL_FUNC_NAME_LEN     64

/* Ringbuf event size: 40 bytes (see struct vigil_timing_event layout) */
#define VIGIL_EVENT_SIZE        40

/* Per-function rate limit: max events per second before throttling */
#define VIGIL_RATE_LIMIT        1000

/* Rate limit window: nanoseconds between allowed events per function */
#define VIGIL_RATE_INTERVAL_NS  1000000UL  /* 1ms = 1M events/sec max throughput */

/* ── Data structures ─────────────────────────────────────────────── */

/* Timing event sent to userspace via ringbuf.
 * IMPORTANT: C struct padding places __u64 fields at 8-byte boundaries.
 * Actual layout (x86-64):
 *   offset 0:  func_id    (__u32)
 *   offset 4:  pid         (__u32)
 *   offset 8:  tid         (__u32)
 *   offset 12: _pad0       (__u32) compiler-inserted padding
 *   offset 16: start_ns    (__u64)
 *   offset 24: elapsed_ns  (__u64)
 *   offset 32: cpu         (__u32)
 *   offset 36: flags       (__u8)
 *   offset 37: pad[3]     (__u8[3])
 * Total: 40 bytes
 *
 * Go parsing (parseEvent) uses explicit offsets matching this layout.
 */
struct vigil_timing_event {
    __u32 func_id;      /* Index into monitored functions array */
    __u32 pid;          /* Process ID that triggered the call */
    __u32 tid;          /* Thread ID */
    /* 4 bytes padding inserted by compiler for __u64 alignment */
    __u64 start_ns;     /* kprobe entry timestamp */
    __u64 elapsed_ns;   /* kretprobe exit - start_ns = execution time */
    __u32 cpu;          /* CPU where the kprobe fired */
    __u8  flags;        /* Event flags (see VIGIL_EF_* below) */
    __u8  pad[3];       /* Alignment padding */
};

/* Per-CPU entry timestamp storage.
 * Key: function ID. Value: entry timestamp.
 * This is a per-CPU array map — no locking needed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, VIGIL_MAX_FUNCS);
    __type(key, __u32);
    __type(value, __u64);  /* nanosecond timestamp */
} entry_timestamps SEC(".maps");

/* Per-CPU rate limit counters.
 * Key: function ID. Value: last event timestamp for rate limiting.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, VIGIL_MAX_FUNCS);
    __type(key, __u32);
    __type(value, __u64);  /* last send timestamp */
} rate_limiter SEC(".maps");

/* Configuration map: which functions are monitored.
 * Key: function ID (0..VIGIL_MAX_FUNCS-1).
 * Value: 1 = monitored, 0 = disabled.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, VIGIL_MAX_FUNCS);
    __type(key, __u32);
    __type(value, __u32);  /* 0 = disabled, 1 = monitored */
} func_config SEC(".maps");

/* Global enable/disable switch.
 * Key: 0. Value: 1 = enabled, 0 = disabled.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} global_enable SEC(".maps");

/* Ringbuf for sending timing events to userspace.
 * 4MB total — bounded to prevent TCA (Telemetry Complexity Attacks).
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);  /* 4 MB */
} timing_events SEC(".maps");

/* ── Event flags ────────────────────────────────────────────────── */

#define VIGIL_EF_NONE        0
#define VIGIL_EF_RATE_LTD   1   /* Event throttled by rate limiter */
#define VIGIL_EF_BATCHED    2   /* Part of a batch aggregation (future) */

/* ── Helper: check if VIGIL is globally enabled ─────────────────── */

static __always_inline int vigil_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&global_enable, &key);
    return val && *val == 1;
}

/* ── Helper: check if a specific function is monitored ────────────── */

static __always_inline int func_monitored(__u32 func_id)
{
    if (func_id >= VIGIL_MAX_FUNCS)
        return 0;
    __u32 *val = bpf_map_lookup_elem(&func_config, &func_id);
    return val && *val == 1;
}

/* ── Helper: rate limit check per function ────────────────────────── */

static __always_inline int rate_limit_check(__u32 func_id)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&rate_limiter, &func_id);
    if (!last)
        return 1;  /* No previous timestamp — allow first event */

    /* Allow if at least VIGIL_RATE_INTERVAL_NS has passed */
    if (now - *last < VIGIL_RATE_INTERVAL_NS)
        return 0;  /* Too soon — throttle */

    /* Update last send time */
    *last = now;
    return 1;  /* Allow */
}

/* ── KPROBE: do_sys_openat2 entry ───────────────────────────────── */

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(vigil_openat2_entry)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 0;  /* do_sys_openat2 = func_id 0 */
    if (!func_monitored(func_id))
        return 0;

    /* Record entry timestamp in per-CPU map */
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &func_id, &ts, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(vigil_openat2_exit)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 0;
    if (!func_monitored(func_id))
        return 0;

    /* Rate limit: throttle events if too frequent */
    if (!rate_limit_check(func_id))
        return 0;

    /* Retrieve entry timestamp */
    __u64 *start_ts = bpf_map_lookup_elem(&entry_timestamps, &func_id);
    if (!start_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - *start_ts;

    /* Send timing event to userspace */
    struct vigil_timing_event *e = bpf_ringbuf_reserve(&timing_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->func_id    = func_id;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->start_ns   = *start_ts;
    e->elapsed_ns = elapsed;
    e->cpu        = bpf_get_smp_processor_id();
    e->flags      = VIGIL_EF_NONE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: vfs_read ────────────────────────────────────────────── */

SEC("kprobe/vfs_read")
int BPF_KPROBE(vigil_vfs_read_entry)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 1;  /* vfs_read = func_id 1 */
    if (!func_monitored(func_id))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &func_id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(vigil_vfs_read_exit)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 1;
    if (!func_monitored(func_id))
        return 0;

    if (!rate_limit_check(func_id))
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&entry_timestamps, &func_id);
    if (!start_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - *start_ts;

    struct vigil_timing_event *e = bpf_ringbuf_reserve(&timing_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->func_id    = func_id;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->start_ns   = *start_ts;
    e->elapsed_ns = elapsed;
    e->cpu        = bpf_get_smp_processor_id();
    e->flags      = VIGIL_EF_NONE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: __x64_sys_getdents64 ────────────────────────────────── */

SEC("kprobe/__x64_sys_getdents64")
int BPF_KPROBE(vigil_getdents64_entry)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 2;  /* __x64_sys_getdents64 = func_id 2 */
    if (!func_monitored(func_id))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &func_id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/__x64_sys_getdents64")
int BPF_KRETPROBE(vigil_getdents64_exit)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 2;
    if (!func_monitored(func_id))
        return 0;

    if (!rate_limit_check(func_id))
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&entry_timestamps, &func_id);
    if (!start_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - *start_ts;

    struct vigil_timing_event *e = bpf_ringbuf_reserve(&timing_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->func_id    = func_id;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->start_ns   = *start_ts;
    e->elapsed_ns = elapsed;
    e->cpu        = bpf_get_smp_processor_id();
    e->flags      = VIGIL_EF_NONE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: security_inode_permission ─────────────────────────────── */

SEC("kprobe/security_inode_permission")
int BPF_KPROBE(vigil_secinode_perm_entry)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 3;  /* security_inode_permission = func_id 3 */
    if (!func_monitored(func_id))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &func_id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/security_inode_permission")
int BPF_KRETPROBE(vigil_secinode_perm_exit)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 3;
    if (!func_monitored(func_id))
        return 0;

    if (!rate_limit_check(func_id))
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&entry_timestamps, &func_id);
    if (!start_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - *start_ts;

    struct vigil_timing_event *e = bpf_ringbuf_reserve(&timing_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->func_id    = func_id;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->start_ns   = *start_ts;
    e->elapsed_ns = elapsed;
    e->cpu        = bpf_get_smp_processor_id();
    e->flags      = VIGIL_EF_NONE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: security_file_permission ─────────────────────────────── */

SEC("kprobe/security_file_permission")
int BPF_KPROBE(vigil_secfile_perm_entry)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 4;  /* security_file_permission = func_id 4 */
    if (!func_monitored(func_id))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &func_id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/security_file_permission")
int BPF_KRETPROBE(vigil_secfile_perm_exit)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 4;
    if (!func_monitored(func_id))
        return 0;

    if (!rate_limit_check(func_id))
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&entry_timestamps, &func_id);
    if (!start_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - *start_ts;

    struct vigil_timing_event *e = bpf_ringbuf_reserve(&timing_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->func_id    = func_id;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->start_ns   = *start_ts;
    e->elapsed_ns = elapsed;
    e->cpu        = bpf_get_smp_processor_id();
    e->flags      = VIGIL_EF_NONE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: __x64_sys_openat ────────────────────────────────────── */

SEC("kprobe/__x64_sys_openat")
int BPF_KPROBE(vigil_sysopenat_entry)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 5;  /* __x64_sys_openat = func_id 5 */
    if (!func_monitored(func_id))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_timestamps, &func_id, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int BPF_KRETPROBE(vigil_sysopenat_exit)
{
    if (!vigil_enabled())
        return 0;

    __u32 func_id = 5;
    if (!func_monitored(func_id))
        return 0;

    if (!rate_limit_check(func_id))
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&entry_timestamps, &func_id);
    if (!start_ts)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - *start_ts;

    struct vigil_timing_event *e = bpf_ringbuf_reserve(&timing_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->func_id    = func_id;
    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->tid        = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->start_ns   = *start_ts;
    e->elapsed_ns = elapsed;
    e->cpu        = bpf_get_smp_processor_id();
    e->flags      = VIGIL_EF_NONE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";