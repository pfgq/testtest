// SPDX-License-Identifier: GPL-2.0
/* khack2 - KernelSU/ReSukiSU/BakaSU uapi shim for 4.19 vendor kernels.
 *
 * Separate from khack1 on purpose: this one patches sys_call_table and runs
 * the reboot hook, i.e. it is the part that can take the kernel down. khack1
 * keeps giving /dev/khack root regardless.
 *
 * What it provides:
 *   - /dev/khack2 ioctl(KHACK_GET_KSU_FD) -> anon_inode "[ksu_driver]" fd
 *   - reboot(0xDEADBEEF, 0xCAFEBABE, 0, &fd) -> same fd, the way the real
 *     driver hands it to the manager app
 *   - enough of the 'K' ioctl uapi (v4) for ksud to see a driver and for
 *     GRANT_ROOT to elevate the caller
 *
 * Params (per boot, from /proc/kallsyms with kptr_restrict=0):
 *   sct_addr   address of sys_call_table
 *   kvoff_addr address of kimage_voffset
 *   msa_addr   address of memstart_addr
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
#include <linux/moduleparam.h>
#include <asm/ptrace.h>
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
static unsigned long kvoff_addr;
static unsigned long msa_addr;
module_param(sct_addr, ulong, 0600);
module_param(kvoff_addr, ulong, 0600);
module_param(msa_addr, ulong, 0600);
MODULE_PARM_DESC(sct_addr, "runtime address of sys_call_table");
MODULE_PARM_DESC(kvoff_addr, "runtime address of kimage_voffset");
MODULE_PARM_DESC(msa_addr, "runtime address of memstart_addr");

static commit_fn p_commit_creds;
static prep_fn   p_prepare_kernel_cred;
static copy_fn   p_copy_to_user;
static copy_fn   p_copy_from_user;
static anonfd_fn p_anon_inode_getfd;
static const struct file_operations ksu_driver_fops;
static long (*p_orig_reboot)(const struct pt_regs *regs);

/* ---- KernelSU uapi v4 (uapi/supercall.h) ---- */
#define KSU_IOCTL_GRANT_ROOT       0x00004b01
#define KSU_IOCTL_GET_INFO         0x80104b02
#define KSU_IOCTL_GET_INFO_LEGACY  0x80004b02
#define KSU_IOCTL_REPORT_EVENT     0x40004b03
#define KSU_IOCTL_SET_SEPOLICY     0xc0004b04
#define KSU_IOCTL_CHECK_SAFEMODE   0x80004b05
#define KSU_IOCTL_UID_GRANTED_ROOT 0xc0004b08
#define KSU_IOCTL_UID_SHOULD_UMOUNT 0xc0004b09
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

struct ksu_get_full_version_cmd {
	char version_full[255];
};

struct ksu_hook_type_cmd {
	char hook_type[32];
};

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
		memcpy(c.version_full, "khack2-4.19.113-42000", 21);
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_HOOK_TYPE: {
		struct ksu_hook_type_cmd c;
		memset(&c, 0, sizeof(c));
		memcpy(c.hook_type, "syscall-table", 13);
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

/* ---- sys_call_table patching via the linear alias ---- */
static int khack_write_kernel_ptr(unsigned long addr, unsigned long val)
{
	u64 kimage_voffset, memstart, phys;
	void *alias;
	unsigned long *slot;

	if (!kvoff_addr || !msa_addr || !sct_addr)
		return -EINVAL;

	kimage_voffset = *(u64 *)kvoff_addr;
	memstart = *(u64 *)msa_addr;
	phys = (u64)addr - kimage_voffset;
	alias = (void *)(unsigned long)((phys - memstart) | PAGE_OFFSET);

	slot = (unsigned long *)alias;

	/* Safety: the alias must read what the image mapping reads. */
	if (*slot != *(unsigned long *)addr) {
		pr_err("khack2: alias check failed, not writing\n");
		return -EINVAL;
	}

	*slot = val;
	__asm__ __volatile__("dsb ish" ::: "memory");

	return (*slot == val) ? 0 : -EIO;
}

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

static long khack2_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (cmd == KHACK_GET_KSU_FD) {
		if (!p_anon_inode_getfd)
			return -ENOSYS;
		return p_anon_inode_getfd("[ksu_driver]", &ksu_driver_fops,
					  NULL, O_RDWR);
	}
	return -EINVAL;
}

static const struct file_operations khack2_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = khack2_ioctl,
	.compat_ioctl = khack2_ioctl,
};

static struct miscdevice khack2_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "khack2",
	.fops  = &khack2_fops,
	.mode  = 0666,
};

static int __init khack2_init(void)
{
	int ret;

	p_commit_creds        = (commit_fn)__symbol_get("commit_creds");
	p_prepare_kernel_cred = (prep_fn)__symbol_get("prepare_kernel_cred");
	p_copy_to_user        = (copy_fn)__symbol_get("__arch_copy_to_user");
	p_copy_from_user      = (copy_fn)__symbol_get("__arch_copy_from_user");
	p_anon_inode_getfd    = (anonfd_fn)__symbol_get("anon_inode_getfd");
	if (!p_commit_creds || !p_prepare_kernel_cred || !p_copy_to_user ||
	    !p_copy_from_user || !p_anon_inode_getfd) {
		pr_err("khack2: __symbol_get failed\n");
		return -ENOENT;
	}

	ret = misc_register(&khack2_dev);
	if (ret) {
		pr_err("khack2: misc_register failed: %d\n", ret);
		return ret;
	}

	if (sct_addr) {
		unsigned long entry = sct_addr + KSU_SYSCALL_REBOOT * sizeof(unsigned long);
		p_orig_reboot = (void *)READ_ONCE(*(unsigned long *)entry);
		if (!khack_write_kernel_ptr(entry, (unsigned long)&khack_reboot_hook))
			pr_info("khack2: reboot hook installed (was %px)\n",
				(void *)p_orig_reboot);
		else
			pr_err("khack2: sys_call_table patch failed\n");
	}

	pr_info("khack2: loaded, ksu uapi v4 shim ready\n");
	return 0;
}

static void __exit khack2_exit(void)
{
	if (sct_addr && p_orig_reboot) {
		unsigned long entry = sct_addr + KSU_SYSCALL_REBOOT * sizeof(unsigned long);
		khack_write_kernel_ptr(entry, (unsigned long)p_orig_reboot);
	}
	misc_deregister(&khack2_dev);
}

module_init(khack2_init);
module_exit(khack2_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack2: KernelSU uapi v4 shim (anon_inode + reboot hook)");
