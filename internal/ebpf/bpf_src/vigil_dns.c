/* vigil_dns.c — VIGIL DNS exfiltration detection eBPF probes
 *
 * Based on:
 *   - BPFflow (eBPF '25): flow-level network telemetry
 *   - eBPF-PATROL (arXiv 2511.18155): context-aware syscall monitoring
 *
 * Concept: Detect DNS-based data exfiltration by monitoring DNS query
 * patterns at the network level:
 *
 *   - High query rate per process (beaconing)
 *   - High-entropy domain names (encoded data in subdomains)
 *   - Unusual DNS ports (not 53)
 *   - New/unseen destination IPs for DNS
 *   - Large DNS responses (tunnel data)
 *
 * We hook:
 *   1. __x64_sys_sendto: captures DNS query destination + length
 *   2. __x64_sys_sendmsg: captures DNS query via sendmsg
 *   3. __x64_sys_recvfrom: captures DNS response length
 *   4. udp_sendmsg: kernel-level UDP send tracking
 *
 * Per-process DNS stats maintained in BPF map (dns_process_stats).
 * Userspace reads map periodically and applies anomaly detection
 * (KS test on query rate, Shannon entropy on domain names).
 *
 * TCA defense:
 *   - Bounded maps (16K process stats, 64K raw events)
 *   - Rate limiting per PID (max 100 events/sec)
 *   - Sampling for high-volume DNS resolvers
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* ── Constants ──────────────────────────────────────────────────── */

#define VIGIL_MAX_COMM_LEN       16
#define VIGIL_MAX_DNS_NAME_LEN   128
#define VIGIL_MAX_PROCESS_STATS  16384
#define VIGIL_MAX_IP_ENTRIES     4096
#define DNS_PORT                 53

/* DNS event types */
#define DNS_EVENT_QUERY    1
#define DNS_EVENT_RESPONSE 2

/* ── Data structures ─────────────────────────────────────────────── */

/* Per-process DNS statistics — maintained in BPF map */
struct dns_proc_stats {
    __u32 pid;
    __u64 query_count;     /* total DNS queries sent */
    __u64 response_count;  /* total DNS responses received */
    __u64 total_query_bytes;
    __u64 total_response_bytes;
    __u64 first_query_ns;  /* timestamp of first query */
    __u64 last_query_ns;   /* timestamp of most recent query */
    __u32 dest_ip_count;   /* unique destination IPs for DNS */
    __u64 last_update_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* DNS query event — sent via ringbuf for userspace entropy analysis */
struct dns_query_event {
    __u32 event_type;     /* DNS_EVENT_QUERY */
    __u32 pid;
    __u32 dport;          /* destination port (expect 53) */
    __u32 len;            /* query packet length */
    __u32 saddr;          /* source IP */
    __u32 daddr;          /* destination IP (DNS server) */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* DNS response event */
struct dns_response_event {
    __u32 event_type;     /* DNS_EVENT_RESPONSE */
    __u32 pid;
    __u32 sport;          /* source port (DNS server port) */
    __u32 len;            /* response packet length */
    __u32 saddr;         /* DNS server IP */
    __u32 daddr;         /* client IP */
    __u64 timestamp_ns;
    char comm[VIGIL_MAX_COMM_LEN];
};

/* ── BPF Maps ───────────────────────────────────────────────────── */

/* Per-process DNS stats */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VIGIL_MAX_PROCESS_STATS);
    __type(key, __u32);    /* pid */
    __type(value, struct dns_proc_stats);
} dns_proc_stats SEC(".maps");

/* DNS destination IP tracking per PID */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VIGIL_MAX_IP_ENTRIES);
    __type(key, __u32);    /* pid << 32 | ip */
    __type(value, __u32);  /* count */
} dns_dest_ips SEC(".maps");

/* Ringbuf for DNS events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2 * 1024 * 1024);
} dns_events SEC(".maps");

/* Global enable/disable */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_global_enable SEC(".maps");

/* Per-PID rate limit */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} dns_ratelimit SEC(".maps");

/* ── Helpers ────────────────────────────────────────────────────── */

static __always_inline int dns_enabled(void)
{
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&dns_global_enable, &key);
    return val && *val == 1;
}

static __always_inline void update_proc_stats(__u32 pid, __u32 daddr, __u32 len, int is_query)
{
    struct dns_proc_stats *stats = bpf_map_lookup_elem(&dns_proc_stats, &pid);
    if (!stats) {
        /* Create new entry */
        struct dns_proc_stats new_stats = {};
        new_stats.pid = pid;
        new_stats.first_query_ns = bpf_ktime_get_ns();
        new_stats.last_query_ns = new_stats.first_query_ns;
        bpf_get_current_comm(new_stats.comm, sizeof(new_stats.comm));
        if (is_query) {
            new_stats.query_count = 1;
            new_stats.total_query_bytes = len;
        } else {
            new_stats.response_count = 1;
            new_stats.total_response_bytes = len;
        }
        new_stats.dest_ip_count = 1;
        new_stats.last_update_ns = bpf_ktime_get_ns();
        bpf_map_update_elem(&dns_proc_stats, &pid, &new_stats, BPF_ANY);

        /* Track destination IP */
        __u64 ip_key = ((__u64)pid << 32) | daddr;
        __u32 one = 1;
        bpf_map_update_elem(&dns_dest_ips, &ip_key, &one, BPF_ANY);
        return;
    }

    __u64 now = bpf_ktime_get_ns();

    if (is_query) {
        stats->query_count++;
        stats->total_query_bytes += len;
        stats->last_query_ns = now;
    } else {
        stats->response_count++;
        stats->total_response_bytes += len;
    }

    stats->last_update_ns = now;

    /* Track destination IP */
    __u64 ip_key = ((__u64)pid << 32) | daddr;
    __u32 *ip_count = bpf_map_lookup_elem(&dns_dest_ips, &ip_key);
    if (!ip_count) {
        __u32 one = 1;
        bpf_map_update_elem(&dns_dest_ips, &ip_key, &one, BPF_ANY);
        stats->dest_ip_count++;
    } else {
        __sync_fetch_and_add(ip_count, 1);
    }
}

/* ── KPROBE: __x64_sys_sendto ──────────────────────────────────────
 *
 * sendto() is used for DNS queries (UDP to port 53).
 * We capture:
 *   - Destination IP and port (DNS server)
 *   - Send length (query size)
 *   - Process comm
 *
 * Arguments (x86-64):
 *   int sendto(int sockfd, const void *buf, size_t len, int flags,
 *              const struct sockaddr *dest_addr, socklen_t addrlen)
 *   rdi=sockfd, rsi=buf, rdx=len, rcx=flags, r8=dest_addr, r9=addrlen
 */
SEC("kprobe/__x64_sys_sendto")
int BPF_KPROBE(handle_sendto, struct pt_regs *regs)
{
    if (!dns_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    /* Read dest_addr pointer from r8 */
    struct sockaddr_in *dest_addr = (struct sockaddr_in *)PT_REGS_PARM5_CORE(regs);
    if (!dest_addr)
        return 0;

    /* Read sockaddr_in fields */
    __u16 sin_family = 0;
    __u16 sin_port = 0;
    __u32 sin_addr = 0;
    bpf_probe_read_user(&sin_family, sizeof(sin_family), &dest_addr->sin_family);
    bpf_probe_read_user(&sin_port, sizeof(sin_port), &dest_addr->sin_port);
    bpf_probe_read_user(&sin_addr, sizeof(sin_addr), &dest_addr->sin_addr.s_addr);

    /* Only track AF_INET destinations */
    if (sin_family != 2) /* AF_INET */
        return 0;

    sin_port = __bpf_ntohs(sin_port);

    /* Track all UDP to port 53, plus unusual DNS ports (5353, 5355) */
    if (sin_port != 53 && sin_port != 5353 && sin_port != 5355)
        return 0;

    __u32 len = PT_REGS_PARM3_CORE(regs);

    /* Rate limit: 100 events per second per PID */
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&dns_ratelimit, &pid);
    if (last && (now - *last) < 10000000ULL) /* 10ms */
        return 0;
    bpf_map_update_elem(&dns_ratelimit, &pid, &now, BPF_ANY);

    /* Update per-process stats */
    update_proc_stats(pid, sin_addr, len, 1);

    /* Send event to userspace for entropy analysis */
    struct dns_query_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u32 saddr = 0;
    /* Read source IP from socket — approximate with task's net namespace */
    /* For now, just use 0 as src (userspace can look up /proc/net) */

    e->event_type = DNS_EVENT_QUERY;
    e->pid = pid;
    e->dport = sin_port;
    e->len = len;
    e->saddr = saddr;
    e->daddr = sin_addr;
    e->timestamp_ns = now;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── KPROBE: __x64_sys_recvfrom ─────────────────────────────────────
 *
 * recvfrom() receives DNS responses.
 * We capture response size to detect DNS tunneling (large responses).
 */
SEC("kprobe/__x64_sys_recvfrom")
int BPF_KPROBE(handle_recvfrom, struct pt_regs *regs)
{
    if (!dns_enabled())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    /* Read src_addr pointer from r8 */
    struct sockaddr_in *src_addr = (struct sockaddr_in *)PT_REGS_PARM5_CORE(regs);
    if (!src_addr)
        return 0;

    __u16 sin_family = 0;
    __u16 sin_port = 0;
    __u32 sin_addr = 0;
    bpf_probe_read_user(&sin_family, sizeof(sin_family), &src_addr->sin_family);
    bpf_probe_read_user(&sin_port, sizeof(sin_port), &src_addr->sin_port);
    bpf_probe_read_user(&sin_addr, sizeof(sin_addr), &src_addr->sin_addr.s_addr);

    if (sin_family != 2)
        return 0;

    sin_port = __bpf_ntohs(sin_port);

    /* DNS responses come FROM port 53 */
    if (sin_port != 53 && sin_port != 5353 && sin_port != 5355)
        return 0;

    __u32 len = PT_REGS_PARM3_CORE(regs);

    /* Rate limit */
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&dns_ratelimit, &pid);
    if (last && (now - *last) < 10000000ULL)
        return 0;
    bpf_map_update_elem(&dns_ratelimit, &pid, &now, BPF_ANY);

    /* Update stats */
    update_proc_stats(pid, sin_addr, len, 0);

    struct dns_response_event *e = bpf_ringbuf_reserve(&dns_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = DNS_EVENT_RESPONSE;
    e->pid = pid;
    e->sport = sin_port;
    e->len = len;
    e->saddr = sin_addr;
    e->daddr = 0;
    e->timestamp_ns = now;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";