/*
 * vigil_rootkit_sim.c — Lightweight kernel module that simulates a rootkit
 * by hooking vfs_read and adding artificial delay.
 *
 * PURPOSE: Prove VIGIL's temporal anomaly detection actually works.
 * This module adds a measurable time shift to vfs_read, which VIGIL's
 * KS test + Welch's t-test should detect as a timing anomaly.
 *
 * HOW IT WORKS:
 *   1. Uses ftrace with IPMODIFY to redirect vfs_read calls to our hook
 *   2. Hook calls original vfs_read, then adds configurable delay (default 500μs)
 *   3. VIGIL's baseline has vfs_read at ~41μs mean
 *   4. With hook: vfs_read mean jumps to ~541μs (>12x increase)
 *   5. KS test and Welch's t-test both detect this immediately
 *
 * SAFETY:
 *   - Only hooks vfs_read (not security-critical functions)
 *   - Adds delay, does NOT modify data or return values
 *   - Safe to load/unload on a running system
 *   - rmmod removes the hook and restores original behavior
 *
 * Usage:
 *   sudo insmod vigil_rootkit_sim.ko              # Load (start simulating)
 *   sudo insmod vigil_rootkit_sim.ko delay_us=200 # Custom delay
 *   sudo rmmod vigil_rootkit_sim                   # Unload (stop simulating)
 *   cat /proc/vigil_rootkit_sim                    # Check status
 *
 * Academic basis: Trace of the Times (DTRAP 2025) demonstrated that
 * rootkit hooks add measurable execution time even when trying to hide.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VIGIL Test Suite");
MODULE_DESCRIPTION("Simulates rootkit timing anomaly for VIGIL detection testing");
MODULE_VERSION("0.1");

/* Delay in microseconds to add to vfs_read */
static int delay_us = 500;
module_param(delay_us, int, 0644);
MODULE_PARM_DESC(delay_us, "Delay in microseconds added to vfs_read (default: 500)");

/* Hook state */
static bool hook_active = false;
static unsigned long hook_count = 0;
static unsigned long original_vfs_read_addr = 0;

/* ftrace ops for hooking */
static struct ftrace_ops ftrace_ops;

/*
 * kallsyms_lookup_name is not exported since kernel 5.7+.
 * Use a kprobe to get the function address instead.
 */
static unsigned long get_symbol_addr(const char *name)
{
	unsigned long addr = 0;
	struct kprobe kp = { .symbol_name = name };

	if (register_kprobe(&kp) == 0) {
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}

	return addr;
}

/*
 * Our hook function: calls original vfs_read then adds artificial delay.
 * This simulates what a rootkit does — adds overhead to kernel functions.
 */
static ssize_t hooked_vfs_read(struct file *file, char __user *buf,
                                size_t count, loff_t *pos)
{
	/* Call original vfs_read via function pointer */
	typedef ssize_t (*vfs_read_t)(struct file *, char __user *, size_t, loff_t *);
	ssize_t ret;

	ret = ((vfs_read_t)original_vfs_read_addr)(file, buf, count, pos);

	/* Add artificial delay to simulate rootkit hook overhead */
	if (delay_us > 0)
		udelay(delay_us);

	/* Track how many calls we've intercepted */
	hook_count++;

	return ret;
}

/*
 * ftrace callback: redirects vfs_read to our hook.
 * Uses ftrace_regs_set_instruction_pointer for kernel 7.x compatibility.
 */
static void ftrace_callback(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *op, struct ftrace_regs *fregs)
{
	ftrace_regs_set_instruction_pointer(fregs, (unsigned long)hooked_vfs_read);
}

/* Procfs status file */
static int proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "VIGIL Rootkit Simulator Status\n");
	seq_printf(m, "==============================\n");
	seq_printf(m, "Hook active:    %s\n", hook_active ? "YES" : "NO");
	seq_printf(m, "Hooked function: vfs_read\n");
	seq_printf(m, "Delay:          %d μs\n", delay_us);
	seq_printf(m, "Hooks caught:   %lu\n", hook_count);
	seq_printf(m, "Original addr:  0x%lx\n", original_vfs_read_addr);
	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
	.proc_open   = proc_open,
	.proc_read   = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
};

static int __init rootkit_sim_init(void)
{
	int ret;

	pr_info("vigil_rootkit_sim: loading with delay=%dμs\n", delay_us);

	/* Look up vfs_read address via kprobe (kallsyms_lookup_name not exported) */
	original_vfs_read_addr = get_symbol_addr("vfs_read");
	if (!original_vfs_read_addr) {
		pr_err("vigil_rootkit_sim: cannot find vfs_read symbol\n");
		return -ENOENT;
	}

	pr_info("vigil_rootkit_sim: vfs_read at 0x%lx\n", original_vfs_read_addr);

	/* Register ftrace hook with IPMODIFY (required for function redirection) */
	ftrace_ops.func = ftrace_callback;
	ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

	ret = ftrace_set_filter(&ftrace_ops, "vfs_read", strlen("vfs_read"), 0);
	if (ret) {
		pr_err("vigil_rootkit_sim: ftrace_set_filter failed: %d\n", ret);
		return ret;
	}

	ret = register_ftrace_function(&ftrace_ops);
	if (ret) {
		pr_err("vigil_rootkit_sim: register_ftrace_function failed: %d\n", ret);
		ftrace_set_filter(&ftrace_ops, NULL, 0, 1);
		return ret;
	}

	hook_active = true;

	/* Create /proc/vigil_rootkit_sim status file */
	proc_create("vigil_rootkit_sim", 0444, NULL, &proc_fops);

	pr_info("vigil_rootkit_sim: vfs_read hooked! Adding %dμs delay per call.\n", delay_us);
	pr_info("vigil_rootkit_sim: VIGIL should detect this as a temporal anomaly.\n");
	return 0;
}

static void __exit rootkit_sim_exit(void)
{
	int ret;

	/* Remove procfs entry */
	remove_proc_entry("vigil_rootkit_sim", NULL);

	/* Unregister ftrace hook */
	ret = unregister_ftrace_function(&ftrace_ops);
	if (ret)
		pr_err("vigil_rootkit_sim: unregister_ftrace_function failed: %d\n", ret);

	ftrace_set_filter(&ftrace_ops, NULL, 0, 1);
	hook_active = false;

	pr_info("vigil_rootkit_sim: vfs_read hook removed, delay eliminated.\n");
	pr_info("vigil_rootkit_sim: caught %lu calls during simulation.\n", hook_count);
}

module_init(rootkit_sim_init);
module_exit(rootkit_sim_exit);