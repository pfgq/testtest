// SPDX-License-Identifier: GPL-2.0
/* khack1 - stable root provider for 4.19 vendor kernels (MODVERSIONS-safe).
 *
 *   1. locate struct selinux_state by scanning the image and clear enforcing
 *   2. /dev/khack: open() gives the caller init_cred, but only if its uid is
 *      listed in allow_uids[] (rewritten inside the image by the manager)
 *   3. the node mode is relaxed twice: once right after misc_register and
 *      again from a delayed work, because ueventd rewrites /dev nodes to
 *      0600 asynchronously and would otherwise win the race.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

typedef void *(*commit_fn)(void *);
typedef void *(*prep_fn)(void *);
typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);

static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;

/* No file IO: the manager rewrites this array inside the module image right
 * before handing it to the chain, so kernel context never has to open
 * anything. volatile keeps the compiler from folding it into a constant. */
#define KMAX_ALLOW 8
static volatile int allow_uids[KMAX_ALLOW] = { -1, -1, -1, -1, -1, -1, -1, -1 };

static bool uid_allowed(u32 uid)
{
	int i;

	for (i = 0; i < KMAX_ALLOW; i++)
		if ((u32)*(volatile int *)&allow_uids[i] == uid && uid != 0xFFFFFFFFu)
			return true;
	return false;
}

/* ---- locate struct selinux_state without kallsyms_lookup_name ---- */
static int khack_clear_enforcing(void)
{
	copy_fn pkr = (copy_fn)__symbol_get("probe_kernel_read");
	unsigned long anchor = (unsigned long)__symbol_get("printk");
	unsigned long lo, hi, a, hit = 0;
	static u8 buf[4096];
	int found = 0;

	if (!pkr || !anchor)
		return -EINVAL;

	anchor &= ~0xFFFUL;
	lo = anchor - 0x800000UL;
	hi = anchor + 0x4000000UL;

	for (a = lo; a < hi; a += sizeof(buf)) {
		unsigned int i;

		if (pkr(buf, (void *)a, sizeof(buf)))
			continue;

		for (i = 0; i + 32 <= sizeof(buf); i++) {
			u8 *b = buf + i;
			u64 avc, ss;
			int j, ok = 1;

			if (b[0] || b[1] != 1 || b[2] || b[3] != 1)
				continue;
			if ((a + i) & 7)
				continue;
			for (j = 4; j < 16; j++)
				if (b[j] > 1) { ok = 0; break; }
			if (!ok)
				continue;

			memcpy(&avc, b + 16, 8);
			memcpy(&ss, b + 24, 8);
			if (avc & 7 || ss & 7)
				continue;
			if (avc < lo || avc >= hi || ss < lo || ss >= hi)
				continue;

			found++;
			hit = a + i;
		}
	}

	if (found != 1)
		return -ENOENT;

	*(u8 *)(hit + 1) = 0;
	return 0;
}

static int khack_open(struct inode *inode, struct file *file)
{
	void *cred;

	if (!uid_allowed(__kuid_val(current_uid())))
		return -EACCES;

	if (!p_prepare_kernel_cred || !p_commit_creds)
		return -ENOENT;

	cred = p_prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	p_commit_creds(cred);
	return 0;
}

static const struct file_operations khack_fops = {
	.owner = THIS_MODULE,
	.open  = khack_open,
};

/* ueventd ignores miscdevice .mode and creates the node 0600 root:root. */
static void khack_relax_mode(void)
{
	struct path p;
	struct iattr attr;

	if (kern_path("/dev/khack", LOOKUP_FOLLOW, &p))
		return;
	memset(&attr, 0, sizeof(attr));
	attr.ia_valid = ATTR_MODE;
	attr.ia_mode  = 0666;
	notify_change(p.dentry, &attr, NULL);
	path_put(&p);
}

static void khack_relax_fn(struct work_struct *w)
{
	khack_relax_mode();
}

static DECLARE_DELAYED_WORK(khack_relax_work, khack_relax_fn);

static struct miscdevice khack_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "khack",
	.fops  = &khack_fops,
	.mode  = 0666,
};

static int __init khack_init(void)
{
	int ret;

	p_commit_creds        = (commit_fn)__symbol_get("commit_creds");
	p_prepare_kernel_cred = (prep_fn)__symbol_get("prepare_kernel_cred");
	if (!p_commit_creds || !p_prepare_kernel_cred)
		return -ENOENT;

	khack_clear_enforcing();

	ret = misc_register(&khack_dev);
	if (ret)
		return ret;

	khack_relax_mode();
	/* Second pass: ueventd applies its own 0600 asynchronously. */
	schedule_delayed_work(&khack_relax_work, 2 * HZ);

	pr_info("khack1: ready\n");
	return 0;
}

static void __exit khack_exit(void)
{
	cancel_delayed_work_sync(&khack_relax_work);
	misc_deregister(&khack_dev);
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
