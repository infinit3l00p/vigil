// © 2026 Dan Vladoiu. All rights reserved.
package ebpf

import "runtime"

// SyscallPrefix returns the kernel's syscall wrapper symbol prefix for the
// current architecture (v0.8.0: ARM64 support).
// x86_64 kernels expose syscall wrappers as __x64_sys_<name>, ARM64 kernels
// as __arm64_sys_<name>. Kprobe attach targets must use the right prefix or
// the attach silently fails on the other architecture.
func SyscallPrefix() string {
	switch runtime.GOARCH {
	case "arm64":
		return "__arm64_sys_"
	default:
		return "__x64_sys_"
	}
}

// SyscallWrapper returns the full kernel symbol for a syscall on the current
// architecture, e.g. SyscallWrapper("setns") → "__x64_sys_setns" on amd64,
// "__arm64_sys_setns" on arm64.
func SyscallWrapper(name string) string {
	return SyscallPrefix() + name
}
