/* vigil_syscall_arg.c — VIGIL syscall argument filter eBPF probes
 *
 * Based on: eBPF-PATROL (arXiv 2511.18155) — 4-component architecture:
 *   Probe Manager → Rule Engine → Context Analyzer → Response Handler
 *
 * Captures syscall arguments for context-aware filtering:
 *   - open/openat: filename + flags (detect path-based attacks)
 *   - connect: destination IP + port (detect C2 callbacks)
 *   - execve: executable path (detect unexpected execution)
 *   - security_capable: capability number (detect privilege escalation)
 *
 * TCA defense:
 *   - Per-function rate limiting (max 100 events/sec)
 *   - Bounded ringbuf (4MB total)
 *   - String truncation (max 256 bytes for paths)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* ── Architecture-portable syscall wrapper names (v0.8.0: ARM64) ────── */
/* SEC names are section metadata only; the actual kprobe attach happens
 * from Go via ebpf.SyscallWrapper() with the same arch logic. */
#if defined(__TARGET_ARCH_arm64)
#define VIGIL_SYSCALL_(n) __arm64_sys_##n
#else
#define VIGIL_SYSCALL_(n) __x64_sys_##n
#endif
#define VIGIL_STR_(x) #x
#define VIGIL_SYSCALL_STR(n) VIGIL_SYSCALL_EXPAND(VIGIL_SYSCALL_(n))
#define VIGIL_SYSCALL_EXPAND(x) VIGIL_STR_(x)


/* ── Constants ──────────────────────────────────────────────────── */

#define VIGIL_MAX_PATH_LEN     256
#define VIGIL_MAX_COMM_LEN     16
#define VIGIL_RATE_LIMIT       100
#define VIGIL_RATE_INTERVAL_NS 10000000UL

/* Syscall argument event types (must match Go constants) */
#define VIGIL_ARG_OPEN         1
#define VIGIL_ARG_CONNECT      2
#define VIGIL_ARG_EXECVE        3
#define VIGIL_ARG_CAPABLE       4

/* ── Data structures ─────────────────────────────────────────────── */

/* Syscall argument event (304 bytes, must match Go parseArgEvent) */
struct vigil_arg_event {
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 flags;
    __u16 port;
    __u16 _pad0;
    __u32 ip_addr;
    __u32 _pad1;
    char   path[VIGIL_MAX_PATH_LEN];
    char   comm[VIGIL_MAX_COMM_LEN];
};

/* Per-function rate limit counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} arg_rate_limiter SEC(".maps");

/* Global enable/disable */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} arg_global_enable SEC(".maps");

/* Ringbuf for syscall argument events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} arg_events SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────── */

static __always_inline int arg_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&arg_global_enable, &key);
    return val && *val == 1;
}

static __always_inline int arg_rate_limit(__u32 type)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&arg_rate_limiter, &type);
    if (!last)
        return 1;

    if (now - *last < VIGIL_RATE_INTERVAL_NS)
        return 0;

    *last = now;
    return 1;
}

/* Read the name pointer from a struct filename.
 * struct filename starts with: const char *name (offset 0 in kernel 7.x)
 * The vmlinux.h has an anonymous struct __filename_head, but we read
 * the name pointer at offset 0 directly since it's always first.
 */
static __always_inline int read_filename_path(struct filename *fn, char *buf, __u32 buf_len)
{
    const char *namep = NULL;
    /* name is the first field of __filename_head, which is the first field
     * of struct filename. Offset 0 = const char *name pointer. */
    bpf_probe_read_kernel(&namep, sizeof(namep), fn);
    if (!namep)
        return -1;
    bpf_probe_read_kernel_str(buf, buf_len, namep);
    return 0;
}

/* ── KPROBE: do_sys_openat2 (file open with path capture) ──────── */

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(vigil_arg_open_entry)
{
    if (!arg_enabled())
        return 0;
    if (!arg_rate_limit(VIGIL_ARG_OPEN))
        return 0;

    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);

    struct vigil_arg_event *e = bpf_ringbuf_reserve(&arg_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = VIGIL_ARG_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->flags = (__u32)PT_REGS_PARM3(ctx);

    read_filename_path(name, e->path, sizeof(e->path));
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: __x64_sys_openat (syscall-level open) ─────────────── */

SEC("kprobe/" VIGIL_SYSCALL_STR(openat))
int BPF_KPROBE(vigil_arg_openat_entry)
{
    if (!arg_enabled())
        return 0;
    if (!arg_rate_limit(VIGIL_ARG_OPEN))
        return 0;

    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);

    struct vigil_arg_event *e = bpf_ringbuf_reserve(&arg_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = VIGIL_ARG_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->flags = (__u32)PT_REGS_PARM3(ctx);

    read_filename_path(name, e->path, sizeof(e->path));
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: security_capable (capability check) ───────────────── */

SEC("kprobe/security_capable")
int BPF_KPROBE(vigil_arg_capable_entry)
{
    if (!arg_enabled())
        return 0;
    if (!arg_rate_limit(VIGIL_ARG_CAPABLE))
        return 0;

    int cap = (int)PT_REGS_PARM3(ctx);

    /* Only monitor high-impact capabilities */
    if (cap != 21 && cap != 12 && cap != 8 && cap != 5 &&
        cap != 17 && cap != 3 && cap != 27 && cap != 9)
        return 0;

    struct vigil_arg_event *e = bpf_ringbuf_reserve(&arg_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = VIGIL_ARG_CAPABLE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->flags = (__u32)cap;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: do_execveat_common (process execution) ────────────── */

SEC("kprobe/do_execveat_common.isra.0")
int BPF_KPROBE(vigil_arg_execve_entry)
{
    if (!arg_enabled())
        return 0;
    if (!arg_rate_limit(VIGIL_ARG_EXECVE))
        return 0;

    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);

    struct vigil_arg_event *e = bpf_ringbuf_reserve(&arg_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = VIGIL_ARG_EXECVE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    read_filename_path(name, e->path, sizeof(e->path));
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: __x64_sys_connect (network connection) ────────────── */

SEC("kprobe/" VIGIL_SYSCALL_STR(connect))
int BPF_KPROBE(vigil_arg_connect_entry)
{
    if (!arg_enabled())
        return 0;
    if (!arg_rate_limit(VIGIL_ARG_CONNECT))
        return 0;

    /* Read sockaddr_in from userspace (16 bytes for IPv4) */
    struct sockaddr_in sin;
    void *uservaddr = (void *)PT_REGS_PARM2(ctx);
    int addrlen = (int)PT_REGS_PARM3(ctx);

    if (addrlen < 2)
        return 0;

    __builtin_memset(&sin, 0, sizeof(sin));
    if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) < 0)
        return 0;

    /* Only handle IPv4 (AF_INET = 2) */
    if (sin.sin_family != 2)
        return 0;

    __u16 port = __bpf_ntohs(sin.sin_port);
    __u32 ip = sin.sin_addr.s_addr;

    /* Skip loopback (127.0.0.1) */
    if (ip == 0x0100007f)
        return 0;

    struct vigil_arg_event *e = bpf_ringbuf_reserve(&arg_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = VIGIL_ARG_CONNECT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->port = port;
    e->ip_addr = ip;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";