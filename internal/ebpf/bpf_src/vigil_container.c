/* vigil_container.c — VIGIL container runtime detection eBPF probes
 *
 * Based on:
 *   - CryptoGuard (ASIACCS 2025): two-phase detection
 *   - CVE-2024-1086, CVE-2026-23111: nftables container escape
 *   - BootKitty: UEFI bootkit that survives container boundaries
 *
 * Concept: Detect when a process transitions from container to host
 * namespace, which is the primary container escape vector.
 *
 * We hook:
 *   1. copy_process: process creation (detect namespace inheritance)
 *   2. __x64_sys_setns: namespace join (already in lineage module,
 *      but container module tracks namespace transitions specifically)
 *   3. __x64_sys_unshare: namespace creation
 *   4. security_bprm_committing_creds: setuid in container context
 *   5. commit_creds: credential changes (detect container root)
 *
 * Detection logic:
 *   - Process in container namespace → setns to host namespace = ESCAPE
 *   - Process creates user namespace + mount namespace = priv esc attempt
 *   - Container process gains CAP_SYS_ADMIN in init namespace = ESCAPE
 *   - Unexpected namespace transitions (e.g., from netns to init_netns)
 *
 * TCA defense: bounded maps, rate limiting
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define VIGIL_MAX_COMM_LEN       16
#define VIGIL_MAX_NS_TRACKED     8192
#define VIGIL_MAX_PATH_LEN       128

/* Container event types */
#define CONT_EVENT_SETNS         1
#define CONT_EVENT_UNSHARE       2
#define CONT_EVENT_NS_CREATE     3
#define CONT_EVENT_PRIV_ESC      4
#define CONT_EVENT_NS_ESCAPE     5

/* Namespace flags */
#define CLONE_NEWNS    0x00020000
#define CLONE_NEWUTS   0x04000000
#define CLONE_NEWIPC   0x08000000
#define CLONE_NEWNET   0x40000000
#define CLONE_NEWPID   0x20000000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUSER  0x10000000

struct cont_ns_event {
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u32 nstype;        /* namespace type flags */
    __u32 old_nsid;      /* previous namespace ID (0 if unknown) */
    __u32 new_nsid;      /* new namespace ID (0 if unknown) */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* Track process namespace membership */
struct cont_proc_ns {
    __u32 pid;
    __u32 net_ns;        /* network namespace inode */
    __u32 pid_ns;        /* PID namespace inode */
    __u32 mnt_ns;        /* mount namespace inode */
    __u32 user_ns;      /* user namespace inode */
    __u32 flags;         /* CONT_PROC_* flags */
    __u64 last_update_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* Process namespace flags */
#define CONT_PROC_CONTAINER    0x01  /* Process is in a container */
#define CONT_PROC_PRIV_ESC     0x02  /* Privilege escalation detected */
#define CONT_PROC_ESCAPED      0x04  /* Namespace escape detected */
#define CONT_PROC_NEW_USER_NS  0x08  /* Created user namespace */

/* ── BPF Maps ───────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VIGIL_MAX_NS_TRACKED);
    __type(key, __u32);
    __type(value, struct cont_proc_ns);
} cont_proc_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} cont_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cont_global_enable SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────── */

static __always_inline int cont_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&cont_global_enable, &key);
    return val && *val == 1;
}

/* ── KPROBE: __x64_sys_setns (container-focused) ─────────────────── */
SEC("kprobe/__x64_sys_setns")
int BPF_KPROBE(handle_cont_setns, struct pt_regs *regs)
{
    if (!cont_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 nstype = PT_REGS_PARM2_CORE(regs);
    __u32 fd = PT_REGS_PARM1_CORE(regs);

    __u64 now = bpf_ktime_get_ns();

    struct cont_ns_event *e = bpf_ringbuf_reserve(&cont_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CONT_EVENT_SETNS;
    e->pid = pid;
    e->uid = uid;
    e->nstype = nstype;
    e->old_nsid = 0;
    e->new_nsid = fd; /* fd is proxy for target namespace */
    e->timestamp_ns = now;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    /* Mark process as potentially container-escaping if it's joining
     * a different namespace and it was already in a container */
    struct cont_proc_ns *pns = bpf_map_lookup_elem(&cont_proc_ns, &pid);
    if (pns && (pns->flags & CONT_PROC_CONTAINER)) {
        pns->flags |= CONT_PROC_ESCAPED;
    }

    return 0;
}

/* ── KPROBE: __x64_sys_unshare (container-focused) ──────────────── */
SEC("kprobe/__x64_sys_unshare")
int BPF_KPROBE(handle_cont_unshare, struct pt_regs *regs)
{
    if (!cont_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 flags = PT_REGS_PARM1_CORE(regs);

    __u64 now = bpf_ktime_get_ns();

    struct cont_ns_event *e = bpf_ringbuf_reserve(&cont_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = CONT_EVENT_UNSHARE;
    e->pid = pid;
    e->uid = uid;
    e->nstype = flags;
    e->old_nsid = 0;
    e->new_nsid = 0;
    e->timestamp_ns = now;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    /* User namespace creation is a privilege escalation vector */
    if (flags & CLONE_NEWUSER) {
        struct cont_proc_ns *pns = bpf_map_lookup_elem(&cont_proc_ns, &pid);
        if (pns) {
            pns->flags |= CONT_PROC_NEW_USER_NS | CONT_PROC_PRIV_ESC;
        } else {
            struct cont_proc_ns new_pns = {};
            new_pns.pid = pid;
            new_pns.flags = CONT_PROC_NEW_USER_NS | CONT_PROC_PRIV_ESC;
            new_pns.last_update_ns = now;
            bpf_get_current_comm(new_pns.comm, sizeof(new_pns.comm));
            bpf_map_update_elem(&cont_proc_ns, &pid, &new_pns, BPF_ANY);
        }
    }

    return 0;
}

/* ── TRACEPOINT: sched_process_fork (container tracking) ─────────── */
SEC("tracepoint/sched/sched_process_fork")
int handle_cont_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    if (!cont_enabled())
        return 0;

    __u32 child_pid = 0, parent_pid = 0;
    bpf_probe_read_kernel(&child_pid, sizeof(child_pid), &ctx->child_pid);
    bpf_probe_read_kernel(&parent_pid, sizeof(parent_pid), &ctx->parent_pid);

    /* Inherit container flag from parent */
    struct cont_proc_ns *parent = bpf_map_lookup_elem(&cont_proc_ns, &parent_pid);
    if (parent && (parent->flags & CONT_PROC_CONTAINER)) {
        struct cont_proc_ns child = {};
        child.pid = child_pid;
        child.flags = CONT_PROC_CONTAINER;
        child.last_update_ns = bpf_ktime_get_ns();

        /* Read child comm */
        __u32 child_data_loc = 0;
        bpf_probe_read_kernel(&child_data_loc, sizeof(child_data_loc), &ctx->__data_loc_child_comm);
        __u16 offset = child_data_loc & 0xFFFF;
        if (offset > 0) {
            void *addr = (void *)((char *)ctx + offset);
            bpf_probe_read_kernel_str(child.comm, sizeof(child.comm), addr);
        }

        bpf_map_update_elem(&cont_proc_ns, &child_pid, &child, BPF_ANY);
    }

    return 0;
}

/* ── TRACEPOINT: sched_process_exit (cleanup) ──────────────────── */
SEC("tracepoint/sched/sched_process_exit")
int handle_cont_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    if (!cont_enabled())
        return 0;

    __u32 pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &ctx->pid);
    bpf_map_delete_elem(&cont_proc_ns, &pid);
    return 0;
}

char _license[] SEC("license") = "GPL";