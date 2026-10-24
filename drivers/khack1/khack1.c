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
#include <linux/namei.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>

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
		int rc = -1; /* UMH disabled: it ran the boot script which chmod 600 the node */
		pr_info("khack1: UMH-RC %d\n", rc);
	}
}


/* misc_register's .mode is applied through the class devnode callback, which
 * some vendor kernels ignore.  Set it explicitly so the node is always
 * openable by unprivileged processes. */
static void khack_force_mode(void)
{
	struct path path;
	struct iattr attr;

	if (kern_path("/dev/ddd", LOOKUP_FOLLOW, &path))
		return;
	attr.ia_valid = ATTR_MODE;
	attr.ia_mode = 0666;
	if (notify_change(&path, &attr, NULL))
		pr_info("khack1: chmod /dev/ddd failed\n");
	else
		pr_info("khack1: /dev/ddd is 0666\n");
	path_put(&path);
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
	.name  = "ddd",
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

	khack_force_mode();

	pr_info("khack1: BUILD 2026-10-24-umh pid=%d\n", current->pid);
	pr_info("khack1: loaded, open /dev/ddd to escalate\n");

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
				rc = -1; /* UMH disabled: script chmod 600 locked us out */
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
