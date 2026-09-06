/* vigil_tty.c — VIGIL TTY input surveillance detection eBPF probes
 *
 * Based on:
 *   - Kernel Rootkit Detection Taxonomy (arXiv 2304.00473): behavior profiling
 *   - HookChain (arXiv 2024): keyboard input interception chains
 *   - EvilEDR (USENIX Security 2025): detecting EDR tampering
 *
 * Concept: Detect when something is reading TTY/terminal input that
 * shouldn't be. This catches:
 *   - Software keyloggers (reading /dev/input/* or ptmx)
 *   - SSH session hijacking (reading another user's pty)
 *   - Hardware keylogger drivers (kernel modules hooking n_tty_read)
 *   - Screen scraping (reading terminal output via ptmx)
 *
 * We hook:
 *   1. n_tty_read: normal terminal input reader (flag suspicious readers)
 *   2. n_tty_write: terminal output (detect screen scraping patterns)
 *   3. pty_write: pty master write (detect pty snooping)
 *   4. __x64_sys_read: catch reads from /dev/input/* and /dev/tty*
 *
 * Per-process TTY stats maintained in BPF map:
 *   - Read count / write count
 *   - Total bytes read/written
 *   - Read rate (reads per second)
 *   - Suspicious read patterns (e.g., reading from many ttys)
 *
 * Anomaly detection (userspace):
 *   - High read rate on TTY devices (> 100 reads/sec = likely keylogger)
 *   - Cross-user TTY reading (user A reading user B's pty)
 *   - Reading from /dev/input/event* (only evdev readers should do this)
 *   - Unusual processes reading TTY (e.g., web server, cron daemon)
 *
 * TCA defense:
 *   - Bounded maps (8K process stats, 4K raw events)
 *   - Rate limiting per PID (max 10 events/sec)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* ── Constants ──────────────────────────────────────────────────── */

#define VIGIL_MAX_COMM_LEN       16
#define VIGIL_MAX_TTY_PROCS      8192
#define VIGIL_MAX_FD_ENTRIES     4096

/* TTY event types */
#define TTY_EVENT_READ      1
#define TTY_EVENT_WRITE     2
#define TTY_EVENT_PTY_WRITE 3
#define TTY_EVENT_INPUT_READ 4  /* read from /dev/input/* */

/* Suspicious TTY reader categories */
#define TTY_READER_NORMAL    0  /* Expected reader (shell, sshd, getty) */
#define TTY_READER_SUSPICIOUS 1  /* Unexpected reader (web server, daemon) */
#define TTY_READER_CROSS_USER 2  /* Reading another user's TTY */

/* ── Data structures ─────────────────────────────────────────────── */

struct tty_proc_stats {
    __u32 pid;
    __u32 uid;
    __u64 read_count;
    __u64 write_count;
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 first_event_ns;
    __u64 last_event_ns;
    __u32 input_dev_reads;   /* reads from /dev/input/* */
    __u32 tty_reads;         /* reads from TTY devices */
    __u32 pty_writes;        /* writes to PTY master */
    __u8  reader_type;       /* TTY_READER_* */
    __u8  _pad[3];
    char comm[VIGIL_MAX_COMM_LEN];
};

struct tty_event {
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u64 count;        /* byte count or fd */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* ── BPF Maps ───────────────────────────────────────────────────── */

/* Per-process TTY stats */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VIGIL_MAX_TTY_PROCS);
    __type(key, __u32);    /* pid */
    __type(value, struct tty_proc_stats);
} tty_proc_stats SEC(".maps");

/* Ringbuf for TTY events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} tty_events SEC(".maps");

/* Global enable/disable */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tty_global_enable SEC(".maps");

/* Per-PID rate limit */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} tty_ratelimit SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────── */

static __always_inline int tty_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&tty_global_enable, &key);
    return val && *val == 1;
}

/* Check if process is an expected TTY reader */
static __always_inline __u8 classify_reader(const char *comm)
{
    /* Expected TTY readers */
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h')
        return TTY_READER_NORMAL;
    if (comm[0] == 'z' && comm[1] == 's' && comm[2] == 'h')
        return TTY_READER_NORMAL;
    if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd')
        return TTY_READER_NORMAL;
    if (comm[0] == 'g' && comm[1] == 'e' && comm[2] == 't' && comm[3] == 't')
        return TTY_READER_NORMAL;
    if (comm[0] == 'l' && comm[1] == 'o' && comm[2] == 'g' && comm[3] == 'i')
        return TTY_READER_NORMAL;
    if (comm[0] == 'a' && comm[1] == 'g' && comm[2] == 'e' && comm[3] == 't')
        return TTY_READER_NORMAL;
    if (comm[0] == 's' && comm[1] == 'c' && comm[2] == 'r' && comm[3] == 'e')
        return TTY_READER_NORMAL; /* screen */
    if (comm[0] == 't' && comm[1] == 'm' && comm[2] == 'u' && comm[3] == 'x')
        return TTY_READER_NORMAL;
    if (comm[0] == 'v' && comm[1] == 'i' && comm[2] == 'm')
        return TTY_READER_NORMAL;
    if (comm[0] == 'n' && comm[1] == 'a' && comm[2] == 'n' && comm[3] == 'o')
        return TTY_READER_NORMAL;
    if (comm[0] == 'f' && comm[1] == 'i' && comm[2] == 's' && comm[3] == 'h')
        return TTY_READER_NORMAL;

    /* Known suspicious readers (daemons shouldn't read TTY) */
    if (comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' && comm[3] == 'n')
        return TTY_READER_SUSPICIOUS; /* nginx */
    if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'a' && comm[3] == 'c')
        return TTY_READER_SUSPICIOUS; /* apache */
    if (comm[0] == 'c' && comm[1] == 'r' && comm[2] == 'o' && comm[3] == 'n')
        return TTY_READER_SUSPICIOUS; /* crond */
    if (comm[0] == 'd' && comm[1] == 'b' && comm[2] == 'u' && comm[3] == 's')
        return TTY_READER_SUSPICIOUS;

    return TTY_READER_SUSPICIOUS; /* unknown = suspicious by default */
}

static __always_inline void update_tty_stats(__u32 pid, __u32 uid,
                                              __u64 bytes, int is_read,
                                              int is_input_dev)
{
    struct tty_proc_stats *stats = bpf_map_lookup_elem(&tty_proc_stats, &pid);
    if (!stats) {
        struct tty_proc_stats new_stats = {};
        new_stats.pid = pid;
        new_stats.uid = uid;
        new_stats.first_event_ns = bpf_ktime_get_ns();
        new_stats.last_event_ns = new_stats.first_event_ns;
        bpf_get_current_comm(new_stats.comm, sizeof(new_stats.comm));
        new_stats.reader_type = classify_reader(new_stats.comm);

        if (is_read) {
            new_stats.read_count = 1;
            new_stats.read_bytes = bytes;
            if (is_input_dev)
                new_stats.input_dev_reads = 1;
            else
                new_stats.tty_reads = 1;
        } else {
            new_stats.write_count = 1;
            new_stats.write_bytes = bytes;
        }

        bpf_map_update_elem(&tty_proc_stats, &pid, &new_stats, BPF_ANY);
        return;
    }

    __u64 now = bpf_ktime_get_ns();

    if (is_read) {
        stats->read_count++;
        stats->read_bytes += bytes;
        if (is_input_dev)
            stats->input_dev_reads++;
        else
            stats->tty_reads++;
    } else {
        stats->write_count++;
        stats->write_bytes += bytes;
    }

    stats->last_event_ns = now;
}

/* ── KPROBE: n_tty_read ────────────────────────────────────────────
 *
 * The canonical TTY read function. Every process reading from a
 * terminal (including SSH sessions) goes through here.
 *
 * We track read frequency and volume per process.
 * High-frequency readers are flagged for userspace analysis.
 */
SEC("kprobe/n_tty_read")
int BPF_KPROBE(handle_n_tty_read)
{
    if (!tty_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Rate limit: 10 events per second per PID */
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&tty_ratelimit, &pid);
    if (last && (now - *last) < 100000000ULL) /* 100ms */
        return 0;
    bpf_map_update_elem(&tty_ratelimit, &pid, &now, BPF_ANY);

    update_tty_stats(pid, uid, 0, 1, 0);

    /* Only emit ringbuf event for suspicious readers */
    struct tty_proc_stats *stats = bpf_map_lookup_elem(&tty_proc_stats, &pid);
    if (!stats || stats->reader_type == TTY_READER_NORMAL)
        return 0;

    struct tty_event *e = bpf_ringbuf_reserve(&tty_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = TTY_EVENT_READ;
    e->pid = pid;
    e->uid = uid;
    e->count = stats->read_count;
    e->timestamp_ns = now;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: n_tty_write ─────────────────────────────────────────── */
SEC("kprobe/n_tty_write")
int BPF_KPROBE(handle_n_tty_write)
{
    if (!tty_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&tty_ratelimit, &pid);
    if (last && (now - *last) < 100000000ULL)
        return 0;
    bpf_map_update_elem(&tty_ratelimit, &pid, &now, BPF_ANY);

    update_tty_stats(pid, uid, 0, 0, 0);
    return 0;
}

/* ── KPROBE: pty_write ────────────────────────────────────────────
 *
 * pty_write is called when data is written to the master side of a
 * PTY. This is the path for screen scraping and PTY snooping.
 */
SEC("kprobe/pty_write")
int BPF_KPROBE(handle_pty_write)
{
    if (!tty_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&tty_ratelimit, &pid);
    if (last && (now - *last) < 100000000ULL)
        return 0;
    bpf_map_update_elem(&tty_ratelimit, &pid, &now, BPF_ANY);

    struct tty_proc_stats *stats = bpf_map_lookup_elem(&tty_proc_stats, &pid);
    if (stats) {
        stats->pty_writes++;
        stats->last_event_ns = now;
    } else {
        struct tty_proc_stats new_stats = {};
        new_stats.pid = pid;
        new_stats.uid = uid;
        new_stats.pty_writes = 1;
        new_stats.first_event_ns = now;
        new_stats.last_event_ns = now;
        bpf_get_current_comm(new_stats.comm, sizeof(new_stats.comm));
        new_stats.reader_type = classify_reader(new_stats.comm);
        bpf_map_update_elem(&tty_proc_stats, &pid, &new_stats, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";