#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xe8213e80, "_printk" },
	{ 0xc3582c54, "ftrace_set_filter" },
	{ 0x48b2cb88, "seq_printf" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xb6377019, "register_kprobe" },
	{ 0x2de0a194, "unregister_kprobe" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x766337ea, "register_ftrace_function" },
	{ 0x1c77f2cc, "proc_create" },
	{ 0x2be27a2d, "seq_read" },
	{ 0x2885ab8e, "seq_lseek" },
	{ 0x3cdc139e, "single_release" },
	{ 0x0fb2af84, "param_ops_int" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x5ed2ae1d, "single_open" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0xa96d32ba, "__udelay" },
	{ 0x2c7db5ac, "remove_proc_entry" },
	{ 0x766337ea, "unregister_ftrace_function" },
	{ 0xa3ed642b, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xe8213e80,
	0xc3582c54,
	0x48b2cb88,
	0xe4de56b4,
	0xbd03ed67,
	0xb6377019,
	0x2de0a194,
	0xd272d446,
	0x766337ea,
	0x1c77f2cc,
	0x2be27a2d,
	0x2885ab8e,
	0x3cdc139e,
	0x0fb2af84,
	0xd272d446,
	0xd272d446,
	0x5ed2ae1d,
	0x5a844b26,
	0xa96d32ba,
	0x2c7db5ac,
	0x766337ea,
	0xa3ed642b,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"_printk\0"
	"ftrace_set_filter\0"
	"seq_printf\0"
	"__ubsan_handle_load_invalid_value\0"
	"__ref_stack_chk_guard\0"
	"register_kprobe\0"
	"unregister_kprobe\0"
	"__stack_chk_fail\0"
	"register_ftrace_function\0"
	"proc_create\0"
	"seq_read\0"
	"seq_lseek\0"
	"single_release\0"
	"param_ops_int\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"single_open\0"
	"__x86_indirect_thunk_rax\0"
	"__udelay\0"
	"remove_proc_entry\0"
	"unregister_ftrace_function\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "AA306CA9C1F40661A514EE8");
