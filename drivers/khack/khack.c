// SPDX-License-Identifier: GPL-2.0
/* khack - root LKM for 4.19 vendor kernels, built to survive MODVERSIONS.
 *
 * Two jobs:
 *  1. /dev/khack: open() gives the caller init_cred, ioctl(KHACK_GET_KSU_FD)
 *     hands out an anon_inode named "[ksu_driver]" that speaks the
 *     ReSukiSU/KernelSU uapi (ioctl 'K' commands).
 *  2. The ksu_driver fd itself: enough of the uapi for ksud to recognise a
 *     driver and for GRANT_ROOT to actually elevate the caller.
 *
 * Every external symbol is resolved with __symbol_get(), so the only imports
 * are module_layout/printk/misc_register/misc_deregister/__symbol_get - the
 * same set whose vendor CRCs we already know match this kernel.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/moduleparam.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/memory.h>

typedef void *(*commit_fn)(void *);
typedef void *(*prep_fn)(void *);
typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);
typedef int (*anonfd_fn)(const char *name, const struct file_operations *fops,
			 void *priv, int flags);

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE
#define KSU_SYSCALL_REBOOT 142

static unsigned long sct_addr;
module_param(sct_addr, ulong, 0600);
MODULE_PARM_DESC(sct_addr, "runtime address of sys_call_table");

static long (*p_orig_reboot)(const struct pt_regs *regs);
static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;
static copy_fn   p_copy_to_user;
static copy_fn   p_copy_from_user;
static anonfd_fn p_anon_inode_getfd;

/* ---- ReSukiSU / KernelSU uapi (uapi/supercall.h, uapi version 4) ---- */
#define KSU_IOCTL_GRANT_ROOT       0x00004b01
#define KSU_IOCTL_GET_INFO         0x80104b02
#define KSU_IOCTL_GET_INFO_LEGACY  0x80004b02
#define KSU_IOCTL_REPORT_EVENT     0x40004b03
#define KSU_IOCTL_SET_SEPOLICY     0xc0004b04
#define KSU_IOCTL_CHECK_SAFEMODE   0x80004b05
#define KSU_IOCTL_UID_GRANTED_ROOT 0xc0004b08
#define KSU_IOCTL_UID_SHOULD_UMOUNT 0xc00004b09
#define KSU_IOCTL_GET_MANAGER_APPID 0x80004b0a
#define KSU_IOCTL_GET_APP_PROFILE  0xc0004b0b
#define KSU_IOCTL_SET_APP_PROFILE  0x40004b0c
#define KSU_IOCTL_GET_FEATURE      0xc0004b0d
#define KSU_IOCTL_SET_FEATURE      0x40004b0e
#define KSU_IOCTL_GET_WRAPPER_FD   0x40004b0f
#define KSU_IOCTL_MANAGE_MARK      0xc0004b10
#define KSU_IOCTL_ADD_TRY_UMOUNT   0x40004b12
#define KSU_IOCTL_GET_SULOG_FD     0x40104b14
#define KSU_IOCTL_GET_FULL_VERSION 0x80004b64
#define KSU_IOCTL_HOOK_TYPE        0x80004b65

/* private: ask /dev/khack for a ksu_driver fd */
#define KHACK_GET_KSU_FD           0x00004b00

#define KSU_VERSION                42000
#define KSU_UAPI_VERSION           4

struct ksu_get_info_cmd {
	u32 version;
	u32 flags;
	u32 features;
	u32 uapi_version;
};

struct ksu_get_info_legacy_cmd {
	u32 version;
	u32 flags;
	u32 features;
};

struct ksu_check_safemode_cmd {
	u8 in_safe_mode;
};

struct ksu_uid_granted_root_cmd {
	u32 uid;
	u8 granted;
};

struct ksu_uid_should_umount_cmd {
	u32 uid;
	u8 should_umount;
};

struct ksu_get_manager_appid_cmd {
	u32 appid;
};

struct ksu_get_feature_cmd {
	u32 feature_id;
	u64 value;
	u8 supported;
};

struct ksu_manage_mark_cmd {
	u32 operation;
	s32 pid;
	u32 result;
};

struct ksu_get_full_version_cmd {
	char version_full[255];
};

struct ksu_hook_type_cmd {
	char hook_type[32];
};


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

	*(u8 *)(hit + 1) = 0;
	pr_info("khack: selinux_state at %px, enforcement cleared\n", (void *)hit);
	return 0;
}


/* ---- sys_call_table patching via the linear alias ----
 * .rodata is mapped read-only in the image mapping, but the same physical
 * pages are also reachable through the linear map, which is writable.
 */
#if defined(pmd_leaf)
#define KHACK_PMD_LEAF(p) pmd_leaf(p)
#elif defined(pmd_sect)
#define KHACK_PMD_LEAF(p) pmd_sect(p)
#else
#define KHACK_PMD_LEAF(p) 0
#endif

static unsigned long khack_phys_from_virt(unsigned long addr)
{
	struct mm_struct *mm = &init_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return 0;
#if defined(pud_sect)
	if (pud_sect(*pud))
		return (pud_pfn(*pud) << PAGE_SHIFT) + (addr & ~PUD_MASK);
#endif
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 0;
	if (KHACK_PMD_LEAF(*pmd))
		return (pmd_pfn(*pmd) << PAGE_SHIFT) + (addr & ~PMD_MASK);
	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;
	return (pte_pfn(*pte) << PAGE_SHIFT) + (addr & ~PAGE_MASK);
}

static int khack_write_kernel_ptr(unsigned long addr, unsigned long val)
{
	unsigned long phys = khack_phys_from_virt(addr);
	void *alias;

	if (!phys)
		return -EFAULT;
	alias = __va(phys);
	*(unsigned long *)alias = val;
	return 0;
}

/* reboot(0xDEADBEEF, 0xCAFEBABE, 0, &fd) -> hand out the ksu_driver fd, the
 * way the real KernelSU driver does, so the manager app finds us. */
static long khack_reboot_hook(const struct pt_regs *regs)
{
	u32 magic1 = (u32)regs->regs[0];
	u32 magic2 = (u32)regs->regs[1];
	unsigned long arg = regs->regs[3];

	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
		int fd = p_anon_inode_getfd("[ksu_driver]", &ksu_driver_fops,
					    NULL, O_RDWR);
		if (fd < 0)
			return fd;
		if (arg && p_copy_to_user((void __user *)arg, &fd, sizeof(fd)))
			return -EFAULT;
		return 0;
	}
	if (p_orig_reboot)
		return p_orig_reboot(regs);
	return -ENOSYS;
}

static long ksu_driver_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case KSU_IOCTL_GET_INFO: {
		struct ksu_get_info_cmd c = {
			.version = KSU_VERSION,
			.flags = 0,
			.features = 0,
			.uapi_version = KSU_UAPI_VERSION,
		};
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_INFO_LEGACY: {
		struct ksu_get_info_legacy_cmd c = {
			.version = KSU_VERSION,
			.flags = 0,
			.features = 0,
		};
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GRANT_ROOT: {
		void *cred = p_prepare_kernel_cred(NULL);
		if (!cred)
			return -ENOMEM;
		p_commit_creds(cred);
		return 0;
	}
	case KSU_IOCTL_CHECK_SAFEMODE: {
		struct ksu_check_safemode_cmd c = { .in_safe_mode = 0 };
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_UID_GRANTED_ROOT: {
		struct ksu_uid_granted_root_cmd c;
		if (p_copy_from_user(&c, uarg, sizeof(c)))
			return -EFAULT;
		c.granted = 1;
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_UID_SHOULD_UMOUNT: {
		struct ksu_uid_should_umount_cmd c;
		if (p_copy_from_user(&c, uarg, sizeof(c)))
			return -EFAULT;
		c.should_umount = 0;
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_MANAGER_APPID: {
		struct ksu_get_manager_appid_cmd c = { .appid = 0 };
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_FEATURE: {
		struct ksu_get_feature_cmd c;
		if (p_copy_from_user(&c, uarg, sizeof(c)))
			return -EFAULT;
		c.value = 0;
		c.supported = 0;
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_FULL_VERSION: {
		struct ksu_get_full_version_cmd c;
		memset(&c, 0, sizeof(c));
		memcpy(c.version_full, "khack-4.19.113-42000", 20);
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_HOOK_TYPE: {
		struct ksu_hook_type_cmd c;
		memset(&c, 0, sizeof(c));
		memcpy(c.hook_type, "anon-inode-shim", 16);
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_REPORT_EVENT:
	case KSU_IOCTL_SET_FEATURE:
	case KSU_IOCTL_MANAGE_MARK:
	case KSU_IOCTL_ADD_TRY_UMOUNT:
	case KSU_IOCTL_SET_SEPOLICY:
	case KSU_IOCTL_SET_APP_PROFILE:
		return 0;
	default:
		return -EINVAL;
	}
}

static const struct file_operations ksu_driver_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ksu_driver_ioctl,
	.compat_ioctl = ksu_driver_ioctl,
};

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

/* ioctl(KHACK_GET_KSU_FD) -> anon_inode fd named "anon_inode:[ksu_driver]" */
static long khack_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (cmd == KHACK_GET_KSU_FD) {
		if (!p_anon_inode_getfd)
			return -ENOSYS;
		return p_anon_inode_getfd("[ksu_driver]", &ksu_driver_fops,
					  NULL, O_RDWR);
	}
	return -EINVAL;
}

static const struct file_operations khack_fops = {
	.owner = THIS_MODULE,
	.open  = khack_open,
	.unlocked_ioctl = khack_ioctl,
	.compat_ioctl = khack_ioctl,
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

	p_copy_to_user   = (copy_fn)__symbol_get("__arch_copy_to_user");
	p_copy_from_user = (copy_fn)__symbol_get("__arch_copy_from_user");
	p_anon_inode_getfd = (anonfd_fn)__symbol_get("anon_inode_getfd");
	if (!p_copy_to_user || !p_copy_from_user || !p_anon_inode_getfd) {
		pr_err("khack: uapi helpers missing (%px %px %px)\n",
		       p_copy_to_user, p_copy_from_user, p_anon_inode_getfd);
		return -ENOENT;
	}

	/* SELinux permissive first: everything after this stops being gated. */
	khack_clear_enforcing();

	/* Escalate whoever is loading us: finit_module() runs in the caller's
	 * context, and that caller is our own code in vendor_modprobe. */
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

	/* Install the reboot hook so the manager app can obtain a driver fd. */
	if (sct_addr) {
		unsigned long entry = sct_addr + KSU_SYSCALL_REBOOT * sizeof(unsigned long);
		unsigned long *slot = (unsigned long *)entry;
		p_orig_reboot = (void *)READ_ONCE(*slot);
		if (!khack_write_kernel_ptr(entry, (unsigned long)&khack_reboot_hook))
			pr_info("khack: reboot hook installed (was %px)\n",
				(void *)p_orig_reboot);
		else
			pr_err("khack: sys_call_table patch failed\n");
	}

	pr_info("khack: loaded, /dev/khack ready (ksu uapi v4 shim)\n");
	return 0;
}

static void __exit khack_exit(void)
{
	misc_deregister(&khack_dev);
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack root helper + minimal KernelSU uapi shim");
