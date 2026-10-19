// SPDX-License-Identifier: GPL-2.0
/*
 * khack - minimal root LKM for 4.19 vendor kernels (Xiaomi lmi / SM8250)
 *
 * Two entry points, no helper binary required:
 *
 *   /dev/khack      ioctl(fd, KHACK_GRANT_ROOT)  -> caller becomes uid 0
 *   /proc/khack     write "1"                    -> caller's parent becomes uid 0
 *
 * The /proc path exists so a plain shell can escalate itself:
 *
 *     echo 1 > /proc/khack
 *
 * (the shell forks a subshell for `echo`, and the module promotes the
 * subshell's parent, i.e. the interactive shell itself).
 *
 * The module must be built with the exact vermagic of the running kernel.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/version.h>

#define KHACK_GRANT_ROOT 0x4b480001UL

/*
 * Promote an arbitrary task to full root credentials.
 * Only safe for a task we control and that is not running on another CPU
 * in the middle of a cred check; this is a one-shot debug helper.
 */
static void khack_escalate(struct task_struct *p)
{
	struct cred *new;

	if (!p)
		return;

	new = prepare_kernel_cred(NULL);
	if (!new) {
		pr_err("khack: prepare_kernel_cred failed\n");
		return;
	}

	task_lock(p);
	rcu_assign_pointer(p->real_cred, new);
	rcu_assign_pointer(p->cred, new);
	task_unlock(p);

	pr_info("khack: task %d (%s) escalated to uid 0\n",
		p->pid, p->comm);
}

static long khack_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	if (cmd != KHACK_GRANT_ROOT)
		return -EINVAL;

	khack_escalate(current);
	return 0;
}

static const struct file_operations khack_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = khack_ioctl,
	.compat_ioctl   = khack_ioctl,
};

static struct miscdevice khack_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "khack",
	.fops  = &khack_fops,
	.mode  = 0666,
};

static ssize_t khack_proc_write(struct file *f, const char __user *buf,
				size_t len, loff_t *off)
{
	char c;

	if (len < 1)
		return -EINVAL;
	if (get_user(c, buf))
		return -EFAULT;

	if (c == '1')
		khack_escalate(current->parent ?: current);

	return len;
}

static const struct file_operations khack_proc_fops = {
	.owner = THIS_MODULE,
	.write = khack_proc_write,
	.llseek = noop_llseek,
};

static struct proc_dir_entry *khack_proc;

static int __init khack_init(void)
{
	int ret;

	pr_info("khack: vermagic = " VERMAGIC_STRING "\n");

	ret = misc_register(&khack_dev);
	if (ret) {
		pr_err("khack: misc_register failed: %d\n", ret);
		return ret;
	}

	khack_proc = proc_create("khack", 0666, NULL, &khack_proc_fops);
	if (!khack_proc) {
		misc_deregister(&khack_dev);
		pr_err("khack: proc_create failed\n");
		return -ENOMEM;
	}

	pr_info("khack: loaded\n");
	return 0;
}

static void __exit khack_exit(void)
{
	if (khack_proc)
		proc_remove(khack_proc);
	misc_deregister(&khack_dev);
	pr_info("khack: unloaded\n");
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack root helper for 4.19 vendor kernels");
MODULE_AUTHOR("local");
