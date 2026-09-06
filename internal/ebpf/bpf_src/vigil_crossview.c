/* vigil_crossview.c — VIGIL cross-view integrity eBPF probes
 *
 * Based on: Kernel-level Rootkit Detection Taxonomy (arXiv 2304.00473)
 *   Cross-view detection: compare kernel view vs userspace view
 *   to find hidden files, processes, and connections.
 *
 * Concept: A rootkit that hides a process from `ps` will still be visible
 * to eBPF tracepoints in the kernel. By comparing what eBPF sees (kernel
 * truth) against what userspace tools see (potentially lied to), we detect
 * hidden objects.
 *
 * Three domains:
 *   1. Process view: eBPF traces fork/exec/exit vs /proc/[pid] enumeration
 *   2. Connection view: eBPF traces TCP state changes vs /proc/net/tcp
 *   3. File view: eBPF traces file opens vs userspace directory listings
 *
 * Uses TRACEPOINTS (not kprobes) for stability across kernel versions:
 *   - sched_process_fork: process creation
 *   - sched_process_exec: process exec (path change)
 *   - sched_process_exit: process exit
 *   - task_rename: process comm change
 *   - inet_sock_set_state: TCP connection state changes
 *
 * TCA defense:
 *   - Bounded BPF maps (HASH maps with max entries)
 *   - Ringbuf events only for state transitions (ESTABLISHED, CLOSE, LISTEN)
 *   - Periodic userspace reconciliation (not streaming)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* ── Constants ──────────────────────────────────────────────────── */

#define VIGIL_MAX_PATH_LEN     128
#define VIGIL_MAX_COMM_LEN     16
#define VIGIL_MAX_CONN_ENTRIES 65536
#define VIGIL_MAX_PROC_ENTRIES 32768

/* Event types for cross-view (must match Go constants) */
#define CV_EVENT_FORK          1
#define CV_EVENT_EXEC          2
#define CV_EVENT_EXIT          3
#define CV_EVENT_RENAME        4
#define CV_EVENT_TCP_STATE     5

/* TCP states (must match Linux TCP_* defines) */
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11
#define TCP_NEW_SYN_RECV 12

/* ── Data structures ─────────────────────────────────────────────── */

/* Scratch buffer for path reads (per-CPU, avoids BPF stack limit) */
struct cv_path_buf {
    char path[VIGIL_MAX_PATH_LEN];
};

/* Process record — stored in BPF map, compared against /proc */
struct cv_process {
    __u32 pid;
    __u32 ppid;
    __u64 start_ns;      /* bpf_ktime_get_ns at fork */
    __u64 exit_ns;       /* 0 if still alive */
    __u32 uid;
    char comm[VIGIL_MAX_COMM_LEN];
    char path[VIGIL_MAX_PATH_LEN]; /* from exec tracepoint */
    __u8 alive;          /* 1=running, 0=exited */
    __u8 _pad[3];
};

/* Connection record — stored in BPF map, compared against /proc/net/tcp */
struct cv_connection {
    __u32 pid;
    __u16 family;         /* AF_INET=2, AF_INET6=10 */
    __u16 protocol;      /* IPPROTO_TCP=6 */
    __u16 sport;
    __u16 dport;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
    __u32 oldstate;
    __u32 newstate;
    __u64 timestamp_ns;
};

/* Fork event — sent to userspace via ringbuf */
struct cv_fork_event {
    __u32 event_type;    /* CV_EVENT_FORK */
    __u32 pid;
    __u32 ppid;
    __u64 timestamp_ns;
    char parent_comm[VIGIL_MAX_COMM_LEN];
    char child_comm[VIGIL_MAX_COMM_LEN];
};

/* Exec event — sent to userspace via ringbuf */
struct cv_exec_event {
    __u32 event_type;    /* CV_EVENT_EXEC */
    __u32 pid;
    __u32 old_pid;       /* pid from exec (may differ if setpid) */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
    char path[VIGIL_MAX_PATH_LEN];
};

/* Exit event — sent to userspace via ringbuf */
struct cv_exit_event {
    __u32 event_type;    /* CV_EVENT_EXIT */
    __u32 pid;
    __u32 group_dead;   /* 1 if last thread */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* Rename event — sent to userspace via ringbuf */
struct cv_rename_event {
    __u32 event_type;    /* CV_EVENT_RENAME */
    __u32 pid;
    __u64 timestamp_ns;
    char oldcomm[VIGIL_MAX_COMM_LEN];
    char newcomm[VIGIL_MAX_COMM_LEN];
};

/* TCP state event — sent to userspace via ringbuf */
struct cv_tcp_event {
    __u32 event_type;    /* CV_EVENT_TCP_STATE */
    __u32 pid;
    __u16 family;
    __u16 protocol;
    __u16 sport;
    __u16 dport;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
    __u32 oldstate;
    __u32 newstate;
    __u64 timestamp_ns;
};

/* ── BPF Maps ───────────────────────────────────────────────────── */

/* Per-CPU scratch buffer for large path reads (avoids BPF stack limit) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cv_path_buf);
} cv_scratch SEC(".maps");

/* Per-CPU scratch buffer for process init (avoids BPF stack limit) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cv_process);
} cv_proc_scratch SEC(".maps");

/* Process hash map: PID → process record */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VIGIL_MAX_PROC_ENTRIES);
    __type(key, __u32);    /* pid */
    __type(value, struct cv_process);
} cv_processes SEC(".maps");

/* Connection hash map: socket pointer → connection record */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VIGIL_MAX_CONN_ENTRIES);
    __type(key, __u64);    /* skaddr (socket pointer) */
    __type(value, struct cv_connection);
} cv_connections SEC(".maps");

/* Ringbuf for cross-view events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} cv_events SEC(".maps");

/* Global enable/disable */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cv_global_enable SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────── */

static __always_inline int cv_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&cv_global_enable, &key);
    return val && *val == 1;
}

/* ── TRACEPOINT: sched_process_fork ─────────────────────────────── */

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (!cv_enabled())
        return 0;

    __u32 child_pid = 0;
    __u32 parent_pid = 0;
    bpf_probe_read_kernel(&child_pid, sizeof(child_pid), &ctx->child_pid);
    bpf_probe_read_kernel(&parent_pid, sizeof(parent_pid), &ctx->parent_pid);

    /* Use per-CPU scratch to avoid large stack allocation */
    __u32 proc_scratch_key = 0;
    struct cv_process *proc = bpf_map_lookup_elem(&cv_proc_scratch, &proc_scratch_key);
    if (!proc)
        return 0;
    __builtin_memset(proc, 0, sizeof(*proc));
    proc->pid = child_pid;
    proc->ppid = parent_pid;
    proc->start_ns = bpf_ktime_get_ns();
    proc->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    proc->alive = 1;

    /* Read child_comm from __data_loc field.
     * __data_loc encodes: low 16 bits = offset from ctx, high 16 bits = length.
     * The ctx pointer points to the start of the tracepoint record,
     * so the string is at (char *)ctx + offset.
     */
    __u32 child_data_loc = 0;
    bpf_probe_read_kernel(&child_data_loc, sizeof(child_data_loc), &ctx->__data_loc_child_comm);
    __u16 child_offset = child_data_loc & 0xFFFF;
    __u16 child_len = child_data_loc >> 16;
    if (child_len > 0 && child_offset > 0) {
        /* The string address is: ctx_base + offset */
        void *str_addr = (void *)((char *)ctx + child_offset);
        bpf_probe_read_kernel_str(proc->comm, sizeof(proc->comm), str_addr);
    }

    bpf_map_update_elem(&cv_processes, &child_pid, proc, BPF_ANY);

    /* Send fork event to userspace */
    struct cv_fork_event *e = bpf_ringbuf_reserve(&cv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CV_EVENT_FORK;
    e->pid = child_pid;
    e->ppid = parent_pid;
    e->timestamp_ns = bpf_ktime_get_ns();

    /* Read parent_comm from __data_loc field */
    __u32 parent_data_loc = 0;
    bpf_probe_read_kernel(&parent_data_loc, sizeof(parent_data_loc), &ctx->__data_loc_parent_comm);
    __u16 parent_offset = parent_data_loc & 0xFFFF;
    __u16 parent_len = parent_data_loc >> 16;
    if (parent_len > 0 && parent_offset > 0) {
        void *parent_addr = (void *)((char *)ctx + parent_offset);
        bpf_probe_read_kernel_str(e->parent_comm, sizeof(e->parent_comm), parent_addr);
    }

    /* Copy child comm from the process record we just built */
    __builtin_memcpy(e->child_comm, proc->comm, sizeof(e->child_comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── TRACEPOINT: sched_process_exec ─────────────────────────────── */

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!cv_enabled())
        return 0;

    __u32 pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &ctx->pid);

    /* Read filename from __data_loc field */
    __u32 filename_loc = 0;
    bpf_probe_read_kernel(&filename_loc, sizeof(filename_loc), &ctx->__data_loc_filename);
    __u16 fn_offset = filename_loc & 0xFFFF;
    __u16 fn_len = filename_loc >> 16;

    /* Use per-CPU scratch buffer to avoid BPF stack limit */
    __u32 scratch_key = 0;
    struct cv_path_buf *scratch = bpf_map_lookup_elem(&cv_scratch, &scratch_key);
    if (!scratch)
        return 0;
    __builtin_memset(scratch->path, 0, sizeof(scratch->path));

    if (fn_len > 0 && fn_offset > 0) {
        void *fn_addr = (void *)((char *)ctx + fn_offset);
        bpf_probe_read_kernel_str(scratch->path, sizeof(scratch->path), fn_addr);
    }

    /* Get current comm via bpf_get_current_comm */
    char current_comm[16] = {};
    bpf_get_current_comm(current_comm, sizeof(current_comm));

    /* Update process record with exec path */
    struct cv_process *proc = bpf_map_lookup_elem(&cv_processes, &pid);
    if (proc) {
        __builtin_memcpy(proc->path, scratch->path, sizeof(proc->path));
        __builtin_memcpy(proc->comm, current_comm, sizeof(proc->comm));
    } else {
        /* Process wasn't in our map (started before VIGIL), add it.
         * Use per-CPU scratch buf as template to avoid large stack var. */
        __u32 proc_key = 0;
        struct cv_process *new_proc = bpf_map_lookup_elem(&cv_proc_scratch, &proc_key);
        if (!new_proc)
            return 0;
        __builtin_memset(new_proc, 0, sizeof(*new_proc));
        new_proc->pid = pid;
        new_proc->ppid = 0; /* unknown — userspace will fill from /proc */
        new_proc->start_ns = bpf_ktime_get_ns();
        new_proc->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        new_proc->alive = 1;
        __builtin_memcpy(new_proc->path, scratch->path, sizeof(new_proc->path));
        __builtin_memcpy(new_proc->comm, current_comm, sizeof(new_proc->comm));
        bpf_map_update_elem(&cv_processes, &pid, new_proc, BPF_ANY);
    }

    /* Send exec event to userspace */
    struct cv_exec_event *e = bpf_ringbuf_reserve(&cv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CV_EVENT_EXEC;
    e->pid = pid;
    __u32 old_pid = 0;
    bpf_probe_read_kernel(&old_pid, sizeof(old_pid), &ctx->old_pid);
    e->old_pid = old_pid;
    e->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(e->comm, current_comm, sizeof(e->comm));
    __builtin_memcpy(e->path, scratch->path, sizeof(e->path));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── TRACEPOINT: sched_process_exit ─────────────────────────────── */

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    if (!cv_enabled())
        return 0;

    __u32 pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &ctx->pid);

    /* Mark process as dead in BPF map */
    struct cv_process *proc = bpf_map_lookup_elem(&cv_processes, &pid);
    if (proc) {
        proc->alive = 0;
        proc->exit_ns = bpf_ktime_get_ns();
    }

    /* Send exit event to userspace */
    struct cv_exit_event *e = bpf_ringbuf_reserve(&cv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CV_EVENT_EXIT;
    e->pid = pid;
    /* Read group_dead as a bool, convert to u32 */
    bool gd = false;
    bpf_probe_read_kernel(&gd, sizeof(gd), &ctx->group_dead);
    e->group_dead = gd ? 1 : 0;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), &ctx->comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── TRACEPOINT: task_rename ─────────────────────────────────────── */

SEC("tracepoint/task/task_rename")
int handle_task_rename(struct trace_event_raw_task_rename *ctx)
{
    if (!cv_enabled())
        return 0;

    __u32 pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &ctx->pid);

    /* Update process comm in BPF map */
    struct cv_process *proc = bpf_map_lookup_elem(&cv_processes, &pid);
    if (proc) {
        bpf_probe_read_kernel_str(proc->comm, sizeof(proc->comm), &ctx->newcomm);
    }

    /* Send rename event to userspace */
    struct cv_rename_event *e = bpf_ringbuf_reserve(&cv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CV_EVENT_RENAME;
    e->pid = pid;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_probe_read_kernel_str(e->oldcomm, sizeof(e->oldcomm), &ctx->oldcomm);
    bpf_probe_read_kernel_str(e->newcomm, sizeof(e->newcomm), &ctx->newcomm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── TRACEPOINT: inet_sock_set_state (TCP state changes) ────────── */

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (!cv_enabled())
        return 0;

    /* Read fields via bpf_probe_read_kernel to satisfy verifier */
    __u16 protocol = 0;
    __u16 family = 0;
    __u16 sport = 0;
    __u16 dport = 0;
    __u32 oldstate = 0;
    __u32 newstate = 0;
    __u64 skaddr = 0;

    bpf_probe_read_kernel(&protocol, sizeof(protocol), &ctx->protocol);
    bpf_probe_read_kernel(&family, sizeof(family), &ctx->family);
    bpf_probe_read_kernel(&sport, sizeof(sport), &ctx->sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), &ctx->dport);
    bpf_probe_read_kernel(&oldstate, sizeof(oldstate), &ctx->oldstate);
    bpf_probe_read_kernel(&newstate, sizeof(newstate), &ctx->newstate);
    bpf_probe_read_kernel(&skaddr, sizeof(skaddr), &ctx->skaddr);

    /* Only track TCP connections */
    if (protocol != 6) /* IPPROTO_TCP */
        return 0;

    /* Only track AF_INET (IPv4) for now */
    if (family != 2) /* AF_INET */
        return 0;

    /* Track established and closed connections in BPF map */
    if (newstate == TCP_ESTABLISHED || newstate == TCP_CLOSE) {
        struct cv_connection conn = {};
        conn.pid = bpf_get_current_pid_tgid() >> 32;
        conn.family = family;
        conn.protocol = protocol;
        conn.sport = sport;
        conn.dport = dport;
        conn.oldstate = oldstate;
        conn.newstate = newstate;
        conn.timestamp_ns = bpf_ktime_get_ns();

        bpf_probe_read_kernel(conn.saddr, 4, &ctx->saddr);
        bpf_probe_read_kernel(conn.daddr, 4, &ctx->daddr);

        bpf_map_update_elem(&cv_connections, &skaddr, &conn, BPF_ANY);
    }

    /* Only send ringbuf events for important state transitions */
    if (newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE &&
        newstate != TCP_LISTEN && newstate != TCP_SYN_SENT)
        return 0;

    struct cv_tcp_event *e = bpf_ringbuf_reserve(&cv_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CV_EVENT_TCP_STATE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->family = family;
    e->protocol = protocol;
    e->sport = sport;
    e->dport = dport;
    e->oldstate = oldstate;
    e->newstate = newstate;
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_probe_read_kernel(e->saddr, 4, &ctx->saddr);
    bpf_probe_read_kernel(e->daddr, 4, &ctx->daddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";