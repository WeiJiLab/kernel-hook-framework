#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <uapi/asm-generic/errno-base.h>
#include <linux/err.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include "include/common_data.h"
#include "include/hook_framework.h"

MODULE_AUTHOR("Liu Tao <ltao@redhat.com>");
MODULE_LICENSE("GPL");

extern void *find_func(const char *name);

static void *vfs_read_fn;
static void *vfs_open_fn;
static void *fuse_open_common_fn;

static int __init test_hookframe_init(void)
{
	int ret = -EFAULT;

	vfs_read_fn = (void *)find_func("vfs_read"); 
	vfs_open_fn = (void *)find_func("vfs_open");
	fuse_open_common_fn = (void *)find_func("fuse_open_common");

	if (!(vfs_read_fn &&
		vfs_open_fn && fuse_open_common_fn)) {
		goto out;
	}

	/*
	* template address is the trampoline where kernel function been hijacked to,
	* codespace address is the original kernel function which been hijacked and repositioned to resume.
	* If you want to replace the whole function, then leave the 3rd parameter of "hijack_target_prepare"
	* to NULL.
	* If you only want to insert your hook before or after a certain function, then leave it to be
	* "GET_CODESPACE_ADDERSS(xx_func)"
	*/

	/*
	  For powerpc, function resume is not supported, currently only function
	  replacement is supported.
	*/
#ifndef _ARCH_POWERPC_
	if (hijack_target_prepare(vfs_read_fn, GET_TEMPLATE_ADDERSS(vfs_read), GET_CODESPACE_ADDERSS(vfs_read))) {
		printk(KERN_ALERT"vfs_read prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(vfs_read_fn)) {
		printk(KERN_ALERT"vfs_read enable error!\n");
		goto out;
	}
#endif
	if (hijack_target_prepare(vfs_open_fn, GET_TEMPLATE_ADDERSS(vfs_open), NULL)) {
		printk(KERN_ALERT"vfs_open prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(vfs_open_fn)) {
		printk(KERN_ALERT"vfs_open enable error!\n");
		goto out;
	}

#ifndef _ARCH_POWERPC_
	if (hijack_target_prepare(fuse_open_common_fn, GET_TEMPLATE_ADDERSS(fuse_open_common), GET_CODESPACE_ADDERSS(fuse_open_common))) {
		printk(KERN_ALERT"fuse_open_common prepare error!\n");
		goto out;
	}
	if (hijack_target_enable(fuse_open_common_fn)) {
		printk(KERN_ALERT"fuse_open_common enable error!\n");
		goto out;
	}
#endif
	return 0;

out:
	hijack_target_disable(vfs_read_fn, true);
	hijack_target_disable(vfs_open_fn, true);
	if (!fuse_open_common_fn) {
		printk(KERN_ALERT"Maybe forget to \"modprobe fuse\"?\n");
	}
	hijack_target_disable(fuse_open_common_fn, true);
	return ret;
}

static void __exit test_hookframe_exit(void)
{
	hijack_target_disable(vfs_read_fn, true);
	hijack_target_disable(vfs_open_fn, true);
	hijack_target_disable(fuse_open_common_fn, true);
	printk(KERN_ALERT"unload hook framework test!\n");
}

module_init(test_hookframe_init);
module_exit(test_hookframe_exit);