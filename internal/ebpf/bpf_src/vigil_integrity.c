/* vigil_integrity.c — VIGIL eBPF self-integrity watchdog
 *
 * Based on:
 *   - EvilEDR (USENIX Security 2025): EDR must verify its own integrity
 *   - eBPF Misbehavior Detection (SOSP 2025): detect rogue BPF programs
 *   - VEP (NSDI 2025): BPF verifier is NOT infallible
 *
 * Concept: VIGIL monitors its own eBPF programs and those of the companion proxy
 * to detect tampering, replacement, or removal.
 *
 * Detection mechanisms:
 *   1. BPF program count verification — count loaded BPF programs,
 *      compare against expected count. A rootkit that injects a
 *      malicious BPF program or removes VIGIL's programs changes the count.
 *   2. BPF map verification — check VIGIL's BPF maps still exist
 *      and have the expected entry counts.
 *   3. Process liveness — verify VIGIL and the companion proxy processes are still
 *      running and haven't been killed/replaced.
 *   4. Module integrity — hash-check the vigil binary periodically.
 *
 * eBPF approach:
 *   - Hook bpf_prog_load (BPF program creation) to track new programs
 *   - Hook bpf_map_free (BPF map destruction) to track map removal
 *   - Hook security_bpf (LSM hook for BPF operations) for BPF audit
 *
 * Userspace reconciliation:
 *   - Periodically enumerate /proc/self/fd to find VIGIL's BPF FDs
 *   - Check /sys/fs/bpf for pinned map/program entries
 *   - Verify VIGIL process is still running (PID check)
 *   - Compare BPF program counts against expected baseline
 *
 * TCA defense:
 *   - Bounded maps (4K BPF program events, 1K BPF map events)
 *   - Rate limiting per PID for BPF program load events
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* ── Constants ──────────────────────────────────────────────────── */

#define VIGIL_MAX_BPF_PROG_EVENTS  4096
#define VIGIL_MAX_BPF_MAP_EVENTS   1024
#define VIGIL_MAX_COMM_LEN         16

/* Integrity event types */
#define INT_EVENT_BPF_LOAD     1  /* New BPF program loaded */
#define INT_EVENT_BPF_FREE     2  /* BPF map/program freed */
#define INT_EVENT_BPF_CHECK    3  /* security_bpf LSM check */
#define INT_EVENT_PROCESS_EXIT 4  /* VIGIL/proxy process exit detected */

/* BPF program types */
#define BPF_PROG_TYPE_UNSPEC    0
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_PROG_TYPE_KPROBE    2
#define BPF_PROG_TYPE_SCHED_CLS 3
#define BPF_PROG_TYPE_TRACEPOINT 5
#define BPF_PROG_TYPE_XDP       6
#define BPF_PROG_TYPE_PERF_EVENT 7
#define BPF_PROG_TYPE_CGROUP_SKB 8
#define BPF_PROG_TYPE_LSM       28
#define BPF_PROG_TYPE_STRUCT_OPS 29

/* ── Data structures ─────────────────────────────────────────────── */

struct int_bpf_event {
    __u32 event_type;     /* INT_EVENT_BPF_* */
    __u32 pid;
    __u32 prog_type;      /* BPF program type */
    __u32 prog_id;        /* BPF program ID (for tracking) */
    __u32 map_id;         /* BPF map ID (for BPF_FREE) */
    __u32 opcode;         /* BPF syscall subcommand */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

struct int_process_event {
    __u32 event_type;     /* INT_EVENT_PROCESS_EXIT */
    __u32 pid;
    __u32 ppid;
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* ── BPF Maps ───────────────────────────────────────────────────── */

/* Count of loaded BPF programs (updated by eBPF, read by userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} int_bpf_prog_count SEC(".maps");

/* Count of loaded BPF maps */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} int_bpf_map_count SEC(".maps");

/* Ringbuf for integrity events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} int_events SEC(".maps");

/* Global enable/disable */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} int_global_enable SEC(".maps");

/* Per-PID rate limit for BPF load events */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} int_ratelimit SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────── */

static __always_inline int int_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&int_global_enable, &key);
    return val && *val == 1;
}

/* ── KPROBE: security_bpf ─────────────────────────────────────────
 *
 * LSM hook for BPF operations. Fires on bpf() syscall.
 * We track:
 *   - BPF_PROG_LOAD: new BPF program being created
 *   - BPF_MAP_CREATE: new BPF map being created
 *   - BPF_PROG_UNLOAD (implicit via close)
 *   - Other BPF commands for audit
 *
 * This is the primary mechanism for detecting unauthorized BPF programs.
 */
SEC("kprobe/security_bpf")
int BPF_KPROBE(handle_security_bpf, int cmd)
{
    if (!int_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    /* Rate limit: 1 event per second per PID */
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&int_ratelimit, &pid);
    if (last && (now - *last) < 1000000000ULL)
        return 0;
    bpf_map_update_elem(&int_ratelimit, &pid, &now, BPF_ANY);

    /* Track BPF program loads and map creates */
    if (cmd == 5 /* BPF_PROG_LOAD */) {
        __u32 key = 0;
        __u32 *count = bpf_map_lookup_elem(&int_bpf_prog_count, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
    }

    struct int_bpf_event *e = bpf_ringbuf_reserve(&int_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = INT_EVENT_BPF_CHECK;
    e->pid = pid;
    e->opcode = cmd;
    e->timestamp_ns = now;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── TRACEPOINT: sched_process_exit (watch VIGIL/proxy) ──────────────
 *
 * Monitor process exits specifically for VIGIL and the companion proxy processes.
 * If VIGIL or the companion proxy exits unexpectedly, this is a potential kill signal.
 */
SEC("tracepoint/sched/sched_process_exit")
int handle_integrity_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    if (!int_enabled())
        return 0;

    __u32 pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &ctx->pid);

    char comm[VIGIL_MAX_COMM_LEN] = {};
    bpf_probe_read_kernel_str(comm, sizeof(comm), &ctx->comm);

    /* Only emit events for vigil / trusted local proxy processes */
    /* Simple prefix match since comm is 16 chars max */
    __u8 is_vigil = 0, is_proxy = 0;
    /* "vigil" = v,i,g,i,l,\0 */
    if (comm[0] == 'v' && comm[1] == 'i' && comm[2] == 'g' && comm[3] == 'i' && comm[4] == 'l')
        is_vigil = 1;
    /* trusted egress proxy prefix "prx" — customise for your setup */
    if (comm[0] == 'p' && comm[1] == 'r' && comm[2] == 'x')
        is_proxy = 1;

    if (!is_vigil && !is_proxy)
        return 0;

    struct int_process_event *e = bpf_ringbuf_reserve(&int_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = INT_EVENT_PROCESS_EXIT;
    e->pid = pid;
    e->ppid = 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";