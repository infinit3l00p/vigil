// Package models defines shared data structures for VIGIL.
package models

// FunctionID constants — must match eBPF C source vigil_kprobe.c
const (
	FuncDoSysOpenat2            = 0 // file open
	FuncVfsRead                 = 1 // file read
	FuncGetdents64              = 2 // directory listing
	FuncSecurityInodePermission  = 3 // inode permission
	FuncSecurityFilePermission   = 4 // file permission
	FuncSysOpenat               = 5 // syscall file open
)

// DetectionCategory enumerates the types of anomalies VIGIL can detect.
type DetectionCategory string

const (
	CatTemporalAnomaly    DetectionCategory = "TEMPORAL_ANOMALY"
	CatSyscallArgFilter   DetectionCategory = "SYSCALL_ARG_FILTER"
	CatCrossView          DetectionCategory = "CROSS_VIEW_MISMATCH"
	CatProcessLineage     DetectionCategory = "PROCESS_LINEAGE_ANOMALY"
	CatSelfIntegrity      DetectionCategory = "SELF_INTEGRITY"
	CatBPFIntegrity       DetectionCategory = "BPF_INTEGRITY"
	CatDNSExfiltration    DetectionCategory = "DNS_EXFILTRATION"
	CatTTYSurveillance    DetectionCategory = "TTY_SURVEILLANCE"
	CatContainerEscape    DetectionCategory = "CONTAINER_ESCAPE"
	CatNetworkFlowAnomaly DetectionCategory = "NETWORK_FLOW_ANOMALY"
	CatBehavioralCluster  DetectionCategory = "BEHAVIORAL_CLUSTER"
)

// ArgEventType constants — must match eBPF C source vigil_syscall_arg.c
const (
	ArgEventNone    = 0 // no event (sentinel/default)
	ArgEventOpen    = 1 // open/openat syscall
	ArgEventConnect = 2 // connect syscall
	ArgEventExecve  = 3 // execve/execveat syscall
	ArgEventCapable = 4 // cap_capable call
)

// ArgEventTypeNames maps event type IDs to human-readable names.
var ArgEventTypeNames = map[uint32]string{
	ArgEventNone:    "NONE",
	ArgEventOpen:    "OPEN",
	ArgEventConnect: "CONNECT",
	ArgEventExecve:  "EXECVE",
	ArgEventCapable: "CAPABLE",
}

// LinuxCapabilities maps capability numbers to names (relevant subset).
var LinuxCapabilities = map[uint32]string{
	21: "CAP_SYS_ADMIN",
	12: "CAP_NET_ADMIN",
	8:  "CAP_SYS_PTRACE",
	5:  "CAP_KILL",
	17: "CAP_SYS_CHROOT",
	3:  "CAP_SYS_RAWIO",
	27: "CAP_SYS_RESOURCE",
	9:  "CAP_LINUX_IMMUTABLE",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	7:  "CAP_SETUID",
	6:  "CAP_SETGID",
}

// VigilVersion is the current version string.
const VigilVersion = "0.5.3"

// Cross-view event types (must match eBPF C defines in vigil_crossview.c)
const (
	CVEventFork     = 1
	CVEventExec     = 2
	CVEventExit     = 3
	CVEventRename   = 4
	CVEventTCPState = 5
)

// CVEventTypeNames maps cross-view event type IDs to human-readable names.
var CVEventTypeNames = map[uint32]string{
	CVEventFork:     "FORK",
	CVEventExec:     "EXEC",
	CVEventExit:     "EXIT",
	CVEventRename:   "RENAME",
	CVEventTCPState: "TCP_STATE",
}

// ── Lineage event types (must match vigil_lineage.c) ──────────────

const (
	LinEventCredChange = 1
	LinEventPtrace     = 2
	LinEventSetNS      = 3
	LinEventUnshare    = 4
	LinEventCapCheck   = 5
	LinEventSUIDExec   = 6
)

var LinEventTypeNames = map[uint32]string{
	LinEventCredChange: "CRED_CHANGE",
	LinEventPtrace:     "PTRACE",
	LinEventSetNS:      "SETNS",
	LinEventUnshare:    "UNSHARE",
	LinEventCapCheck:   "CAP_CHECK",
	LinEventSUIDExec:   "SUID_EXEC",
}

// Lineage node flags (must match vigil_lineage.c LNF_* defines)
const (
	LNFSUIDExec   = 0x01
	LNFSGIDExec   = 0x02
	LNFPrivEsc    = 0x04
	LNFContainer  = 0x08
	LNFPtraced    = 0x10
	LNFNamespace  = 0x20
	LNFSuspicious = 0x40
)

var LineageFlagNames = map[uint32]string{
	LNFSUIDExec:   "SUID_EXEC",
	LNFSGIDExec:   "SGID_EXEC",
	LNFPrivEsc:    "PRIV_ESC",
	LNFContainer:  "CONTAINER",
	LNFPtraced:    "PTRACED",
	LNFNamespace:  "NAMESPACE",
	LNFSuspicious: "SUSPICIOUS",
}

// ── Integrity event types (must match vigil_integrity.c) ──────────

const (
	IntEventBPFLoad     = 1
	IntEventBPFFree      = 2
	IntEventBPFCheck     = 3
	IntEventProcessExit = 4
)

var IntEventTypeNames = map[uint32]string{
	IntEventBPFLoad:     "BPF_LOAD",
	IntEventBPFFree:     "BPF_FREE",
	IntEventBPFCheck:    "BPF_CHECK",
	IntEventProcessExit: "PROCESS_EXIT",
}

// ── DNS event types (must match vigil_dns.c) ──────────────────────

const (
	DNSEventQuery    = 1
	DNSEventResponse = 2
)

var DNSEventTypeNames = map[uint32]string{
	DNSEventQuery:    "DNS_QUERY",
	DNSEventResponse: "DNS_RESPONSE",
}

// ── TTY event types (must match vigil_tty.c) ──────────────────────

const (
	TTYEventRead      = 1
	TTYEventWrite     = 2
	TTYEventPtyWrite  = 3
	TTYEventInputRead = 4
)

var TTYEventTypeNames = map[uint32]string{
	TTYEventRead:      "TTY_READ",
	TTYEventWrite:     "TTY_WRITE",
	TTYEventPtyWrite:  "PTY_WRITE",
	TTYEventInputRead: "INPUT_READ",
}

// ── Container event types (must match vigil_container.c) ──────────

const (
	ContEventSetNS     = 1
	ContEventUnshare   = 2
	ContEventNSCreate  = 3
	ContEventPrivEsc   = 4
	ContEventNSEscape  = 5
)

var ContEventTypeNames = map[uint32]string{
	ContEventSetNS:    "CONT_SETNS",
	ContEventUnshare:  "CONT_UNSHARE",
	ContEventNSCreate: "CONT_NS_CREATE",
	ContEventPrivEsc:  "CONT_PRIV_ESC",
	ContEventNSEscape: "CONT_NS_ESCAPE",
}

// ── Flow event types (must match vigil_flow.c) ────────────────────

const (
	FlowEventConnect   = 1
	FlowEventAccept    = 2
	FlowEventTCPState  = 3
	FlowEventSend      = 4
	FlowEventRecv      = 5
)

var FlowEventTypeNames = map[uint32]string{
	FlowEventConnect:  "FLOW_CONNECT",
	FlowEventAccept:   "FLOW_ACCEPT",
	FlowEventTCPState: "FLOW_TCP_STATE",
	FlowEventSend:     "FLOW_SEND",
	FlowEventRecv:     "FLOW_RECV",
}

// Namespace type flag names
var NamespaceFlagNames = map[uint32]string{
	0x00020000: "CLONE_NEWNS",
	0x04000000: "CLONE_NEWUTS",
	0x08000000: "CLONE_NEWIPC",
	0x40000000: "CLONE_NEWNET",
	0x20000000: "CLONE_NEWPID",
	0x02000000: "CLONE_NEWCGROUP",
	0x10000000: "CLONE_NEWUSER",
}

// Ptrace request names (subset)
var PtraceRequestNames = map[uint32]string{
	0:  "PTRACE_TRACEME",
	1:  "PTRACE_PEEKTEXT",
	2:  "PTRACE_PEEKDATA",
	3:  "PTRACE_PEEKUSR",
	4:  "PTRACE_POKETEXT",
	5:  "PTRACE_POKEDATA",
	6:  "PTRACE_POKEUSR",
	12: "PTRACE_SINGLESTEP",
	13: "PTRACE_ATTACH",
	16: "PTRACE_DETACH",
	24: "PTRACE_SETOPTIONS",
}