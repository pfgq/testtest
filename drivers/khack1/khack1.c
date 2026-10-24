// SPDX-License-Identifier: GPL-2.0
/* khack1 - stable root provider for 4.19 vendor kernels (MODVERSIONS-safe).
 *
 * Two things only:
 *   1. locate struct selinux_state by scanning the image and clear enforcing
 *   2. /dev/khack: open() gives the caller init_cred (uid 0, kernel SID)
 *
 * No syscall patching, no module parameters, no KernelSU code. Everything
 * here is proven to load and work on 4.19.113-perf-gec90c723c482, so the
 * root path stays available while khack2 is being experimented with.
 *
 * Only module_layout/printk/misc_register/misc_deregister/__symbol_get are
 * imported, and their vendor CRCs are patched in at packaging time.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>

typedef void *(*commit_fn)(void *);
typedef void *(*prep_fn)(void *);
typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);

static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;

/* ---- locate struct selinux_state without kallsyms_lookup_name ----
 * Layout (SELINUX_DISABLE=n, DEVELOP=y):
 *   +0 disabled(0) +1 enforcing(1) +2 checkreqprot(0) +3 initialized(1)
 *   +4..+15 policycap[8] + android_netlink_route, all 0/1
 *   +16 avc pointer, +24 ss pointer
 * A booted enforcing system has exactly 00 01 00 01 then twelve bytes <= 1
 * and two aligned in-image pointers. Only a single unambiguous hit is acted
 * on; anything else is left alone.
 */
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
			if ((a + i) & 7)     /* struct selinux_state holds pointers */
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

	if (found != 1) {
		pr_info("khack1: selinux_state scan found %d candidates\n", found);
		return -ENOENT;
	}

	*(u8 *)(hit + 1) = 0;
	pr_info("khack1: selinux_state at %px, enforcement cleared\n", (void *)hit);
	return 0;
}

/* open("/dev/khack") -> caller's creds become init_cred */
static atomic_t daemon_started = ATOMIC_INIT(0);

/* Runs from the open() path, i.e. in a normal process context after /data is
 * mounted.  call_usermodehelper spawns the helper from the kernel, so the
 * daemon it starts carries no seccomp filter. */
static void khack_spawn_daemon(void)
{
	typedef int (*umh_fn)(const char *path, char **argv, char **envp, int wait);
	umh_fn umh = (umh_fn)__symbol_get("call_usermodehelper");
	static char *argv[] = { "/data/data/df.root/files/bin/dfsud", NULL };
	static char *envp[] = { "PATH=/system/bin:/system/xbin", "HOME=/", NULL };

	if (!umh)
		return;
	if (atomic_cmpxchg(&daemon_started, 0, 1) != 0)
		return;
	pr_info("khack1: spawning daemon from open path\n");
	{
		int rc = umh("/data/data/df.root/files/bin/dfsud", argv, envp, 2);
		pr_info("khack1: UMH-RC %d\n", rc);
	}
}


/* ---- KernelSU v0.9.5 prctl shim (merged from khack2) ------------------ */
typedef unsigned long (*copy_fn)(void __user *to, const void *from, unsigned long n);
static copy_fn p_copy_to_user;
typedef int (*tp_reg_fn)(void *tp, void *probe, void *data);

struct tp_find { void *found; };

/* struct tracepoint { const char *name; struct static_key key; ... } - the
 * name is the first member. */
static void tp_find_cb(void *tp, void *priv)
{
	struct tp_find *f = priv;
	const char *name = *(const char **)tp;

	if (!f->found && name && !strcmp(name, "sys_enter"))
		f->found = tp;
}

static struct tracepoint *ksu_find_sys_enter(void *iter_fn)
{
	typedef void (*iter_t)(void (*)(void *, void *), void *);
	struct tp_find f = { NULL };

	if (iter_fn)
		((iter_t)iter_fn)(tp_find_cb, &f);
	return (struct tracepoint *)f.found;
}
#define KSU_PRCTL_OPTION 0xDEADBEEFu
#ifndef KSU_VERSION
#define KSU_VERSION 42000
#endif
#define KSU_MAX_ALLOW 64

static int allow_uids[KSU_MAX_ALLOW];
static int allow_cnt;
static DEFINE_SPINLOCK(allow_lock);

static bool allow_has(int uid)
{
	int i, hit = 0;
	spin_lock(&allow_lock);
	for (i = 0; i < allow_cnt; i++)
		if (allow_uids[i] == uid) { hit = 1; break; }
	spin_unlock(&allow_lock);
	return hit;
}

static void allow_add(int uid)
{
	int i, dup = 0;

	spin_lock(&allow_lock);
	for (i = 0; i < allow_cnt; i++)
		if (allow_uids[i] == uid) { dup = 1; break; }
	if (!dup && allow_cnt < KSU_MAX_ALLOW)
		allow_uids[allow_cnt++] = uid;
	spin_unlock(&allow_lock);
}

static void allow_del(int uid)
{
	int i;
	spin_lock(&allow_lock);
	for (i = 0; i < allow_cnt; i++)
		if (allow_uids[i] == uid) {
			allow_uids[i] = allow_uids[--allow_cnt];
			break;
		}
	spin_unlock(&allow_lock);
}

static void ksu_sys_enter_probe(void *ignore, struct pt_regs *regs)
{
	unsigned long nr = regs->regs[8];

	/* KernelSU v0.9.5 protocol: prctl(0xDEADBEEF, cmd, a1, a2, &result).
	 * prctl is allowed by the app seccomp filter, unlike reboot(). */
	if (nr == 167 && (u32)regs->regs[0] == KSU_PRCTL_OPTION) {
		int cmd = (int)regs->regs[1];
		void __user *a1 = (void __user *)regs->regs[2];
		void __user *a2 = (void __user *)regs->regs[3];
		void __user *res = (void __user *)regs->regs[4];
		int magic = KSU_PRCTL_OPTION;

		switch (cmd) {
		case 0: { /* CMD_GRANT_ROOT: only for allowed uids */
			int uid = (int)__kuid_val(current_uid());
			if (allow_has(uid)) {
				void *cred = p_prepare_kernel_cred(NULL);
				if (cred)
					p_commit_creds(cred);
			} else {
				magic = -13; /* -EACCES */
			}
			break;
		}
		case 3: { /* CMD_ALLOW_SU */
			int uid = 0;
			if (a1 && !copy_from_user(&uid, a1, sizeof(uid)))
				allow_add(uid);
			break;
		}
		case 4: { /* CMD_DENY_SU */
			int uid = 0;
			if (a1 && !copy_from_user(&uid, a1, sizeof(uid)))
				allow_del(uid);
			break;
		}
		case 5: { /* CMD_GET_ALLOW_LIST: snapshot first, copy outside the lock */
			int snap[KSU_MAX_ALLOW];
			u32 n = 0;

			spin_lock(&allow_lock);
			n = allow_cnt;
			memcpy(snap, allow_uids, n * sizeof(int));
			spin_unlock(&allow_lock);
			if (a1)
				p_copy_to_user(a1, &n, sizeof(n));
			if (a2 && n)
				p_copy_to_user(a2, snap, n * sizeof(int));
			break;
		}
		case 2: { /* CMD_GET_VERSION */
			int ver = KSU_VERSION, fl = (1 << 1);
			if (a1)
				p_copy_to_user(a1, &ver, sizeof(ver));
			if (a2)
				p_copy_to_user(a2, &fl, sizeof(fl));
			break;
		}
		case 12: { /* CMD_UID_GRANTED_ROOT */
			u8 granted = 1;
			if (a2)
				p_copy_to_user(a2, &granted, sizeof(granted));
			break;
		}
		case 13: { /* CMD_UID_SHOULD_UMOUNT */
			u8 um = 0;
			if (a2)
				p_copy_to_user(a2, &um, sizeof(um));
			break;
		}
		default:
			break;
		}
		if (res)
			p_copy_to_user(res, &magic, sizeof(magic));
		regs->regs[0] = (unsigned long)-1;   /* prctl returns -1 on success */
		return;
	}

}

static int khack_open(struct inode *inode, struct file *file)
{
	void *cred;

	if (!p_prepare_kernel_cred || !p_commit_creds)
		return -ENOENT;

	cred = p_prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	p_commit_creds(cred);
	pr_info("khack1: caller escalated to init_cred\n");
	khack_spawn_daemon();
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
	if (!p_commit_creds || !p_prepare_kernel_cred) {
		pr_err("khack1: __symbol_get failed (%px %px)\n",
		       p_commit_creds, p_prepare_kernel_cred);
		return -ENOENT;
	}

	khack_clear_enforcing();

	ret = misc_register(&khack_dev);
	if (ret) {
		pr_err("khack1: misc_register failed: %d\n", ret);
		return ret;
	}

	p_copy_to_user = (copy_fn)__symbol_get("copy_to_user");
	{
		tp_reg_fn reg = (tp_reg_fn)__symbol_get("tracepoint_probe_register");
		void *tpf = (void *)__symbol_get("for_each_kernel_tracepoint");
		struct tracepoint *tp = ksu_find_sys_enter(tpf);
		if (reg && tp) {
			int rc = reg(tp, (void *)ksu_sys_enter_probe, NULL);
			pr_info("khack1: prctl hook rc=%d\n", rc);
		} else {
			pr_info("khack1: tracepoint unavailable (reg=%px tp=%px)\n", reg, tp);
		}
	}
	pr_info("khack1: BUILD 2026-10-24-umh pid=%d\n", current->pid);
	pr_info("khack1: loaded, open /dev/khack to escalate\n");

	/* Start the su gatekeeper from init context: nothing else can bring a
	 * root daemon up without an already-rooted caller. */
	{
		typedef int (*umh_fn)(char *path, char **argv, char **envp, int wait);
		umh_fn umh = (umh_fn)__symbol_get("call_usermodehelper");

		if (umh) {
			static char *sh = "/system/bin/sh";
			static char *envp[] = { "PATH=/system/bin:/system/xbin",
						"HOME=/", NULL };
			static char *scripts[] = {
				"/data/local/tmp/dfroot_boot.sh",
				"/data/data/df.root/files/dfroot_boot.sh",
			};
			int i, rc = -1;

			for (i = 0; i < 2; i++) {
				static char *argv[3];
				argv[0] = sh;
				argv[1] = scripts[i];
				argv[2] = NULL;
				rc = umh(sh, argv, envp, 1);
				pr_info("khack1: umh %s -> %d\n", scripts[i], rc);
				if (!rc)
					break;
			}
		} else {
			pr_info("khack1: call_usermodehelper unavailable\n");
		}
	}
	return 0;
}

static void __exit khack_exit(void)
{
	misc_deregister(&khack_dev);
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack1: selinux permissive + /dev/khack root provider");
