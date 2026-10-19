// SPDX-License-Identifier: GPL-2.0
/*
 * khack - minimal root LKM for 4.19 vendor kernels (Xiaomi lmi / SM8250)
 *
 * Design constraint: the module may be built against a kernel tree whose
 * struct layouts differ from the running vendor kernel, so it must never
 * touch struct offsets.  Everything goes through exported helpers:
 *
 *   open("/dev/khack")            -> caller's creds become init_cred (uid 0)
 *   ioctl(fd, KHACK_GRANT_ROOT)   -> same, for callers that keep the fd
 *
 * A shell can escalate itself without any helper binary:
 *
 *     exec 3</dev/khack
 *     id
 *
 * The open() happens in the shell process, so commit_creds() applies to it.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define KHACK_GRANT_ROOT 0x4b480001UL

static void khack_grant_current(void)
{
	struct cred *new;

	new = prepare_kernel_cred(NULL);
	if (!new) {
		pr_err("khack: prepare_kernel_cred failed\n");
		return;
	}

	commit_creds(new);
	pr_info("khack: pid %d (%s) -> uid %d\n",
		current->pid, current->comm, current_uid().val);
}

static int khack_open(struct inode *inode, struct file *file)
{
	khack_grant_current();
	return 0;
}

static long khack_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	if (cmd != KHACK_GRANT_ROOT)
		return -EINVAL;

	khack_grant_current();
	return 0;
}

static const struct file_operations khack_fops = {
	.owner          = THIS_MODULE,
	.open           = khack_open,
	.unlocked_ioctl = khack_ioctl,
	.compat_ioctl   = khack_ioctl,
};

static struct miscdevice khack_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "khack",
	.fops  = &khack_fops,
	.mode  = 0666,
};

static int __init khack_init(void)
{
	int ret;

	ret = misc_register(&khack_dev);
	if (ret) {
		pr_err("khack: misc_register failed: %d\n", ret);
		return ret;
	}

	pr_info("khack: loaded, open /dev/khack to escalate\n");
	return 0;
}

static void __exit khack_exit(void)
{
	misc_deregister(&khack_dev);
	pr_info("khack: unloaded\n");
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack root helper for 4.19 vendor kernels");
MODULE_AUTHOR("local");
