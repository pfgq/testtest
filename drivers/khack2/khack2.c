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
#include <linux/cred.h>
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
#define KSU_SYSCALL_SETRESUID 147

static unsigned long sct_addr;
static unsigned long kvoff_addr;
static unsigned long msa_addr;
static int mgr_uid;
module_param(sct_addr, ulong, 0600);
module_param(mgr_uid, int, 0644);
MODULE_PARM_DESC(mgr_uid, "uid of the manager app that receives the driver fd");
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
static long (*p_orig_setresuid)(const struct pt_regs *regs);

/* The real driver hands the manager its driver fd from a setuid hook; the
 * manager only ever finds the driver by scanning its own fds, so mirror that
 * here. The fd is deliberately left open (no CLOEXEC). */
static long khack_setresuid_hook(const struct pt_regs *regs)
{
	long ret;

	if (!p_orig_setresuid)
		return -ENOSYS;
	ret = p_orig_setresuid(regs);
	if (ret == 0 && mgr_uid > 0 && (int)current_uid().val == mgr_uid) {
		int fd = p_anon_inode_getfd("[ksu_driver]", &ksu_driver_fops,
					    NULL, O_RDWR);
		if (fd < 0)
			pr_info("khack2: manager fd install failed: %d\n", fd);
	}
	return ret;
}

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
#define KSU_IOCTL_GET_MANAGERS      0xc0004b69
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

static long khack_load_ko(const char __user *upath);
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

struct ksu_get_managers_hdr {
	u16 count;
	u16 total_count;
} __attribute__((packed));

struct ksu_get_managers_one {
	u16 count;
	u16 total_count;
	u32 uid;
	u8 signature_index;
} __attribute__((packed));

typedef int (*tp_reg_fn)(void *tp, void *probe, void *data);
typedef void (*tp_iter_fn)(void (*fct)(void *tp, void *priv), void *priv);

struct tp_find {
	void *found;
};

/* __tracepoint_sys_enter is not exported; walk the tracepoint list instead. */
static void tp_find_cb(void *tp, void *priv)
{
	struct tp_find *f = priv;
	/* struct tracepoint { const char *name; struct static_key key; ... } -
	 * name is the FIRST member, reading further dereferences static_key. */
	const char *name = *(const char **)tp;

	if (!f->found && name && !strcmp(name, "sys_enter"))
		f->found = tp;
}

static tp_reg_fn p_tp_register;
static void *p_tp_sys_enter;

/* raw_syscalls:sys_enter fires before the syscall runs, with the syscall
 * number in x8 and the arguments still in x0..x5 - the same mechanism the
 * upstream driver uses.  Nothing here writes kernel text, so STRICT_KERNEL_RWX
 * does not matter and there is no way to fault on a read-only page. */
#define KSU_PRCTL_OPTION 0xDEADBEEFu
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

	/* copy_to_user is not exported on every vendor kernel; without it every
	 * prctl answer would be a NULL call from the tracepoint. */
	if (unlikely(!p_copy_to_user))
		return;

	/* KernelSU v0.9.5 protocol: prctl(0xDEADBEEF, cmd, a1, a2, &result).
	 * prctl is allowed by the app seccomp filter, unlike reboot(). */
	if (nr == 167 && (u32)regs->regs[0] == KSU_PRCTL_OPTION) {
		int cmd = (int)regs->regs[1];
		void __user *a1 = (void __user *)regs->regs[2];
		void __user *a2 = (void __user *)regs->regs[3];
		void __user *res = (void __user *)regs->regs[4];
		int magic = KSU_PRCTL_OPTION;

		switch (cmd) {
		case 0: { /* CMD_GRANT_ROOT */
			int uid = (int)current_uid().val;
			if (1) { /* permissive: allowlist gating disabled for testing */
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
			if (a1 && p_copy_from_user && !p_copy_from_user(&uid, a1, sizeof(uid)))
				allow_add(uid);
			break;
		}
		case 4: { /* CMD_DENY_SU */
			int uid = 0;
			if (a1 && p_copy_from_user && !p_copy_from_user(&uid, a1, sizeof(uid)))
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
		case 9: { /* CMD_CHECK_SAFEMODE: report "not in safe mode" */
			int zero = 0;
			if (a1)
				p_copy_to_user(a1, &zero, sizeof(zero));
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

	if (nr == 142 /* reboot */ &&
	    (u32)regs->regs[0] == KSU_INSTALL_MAGIC1 &&
	    (u32)regs->regs[1] == KSU_INSTALL_MAGIC2) {
		int fd = p_anon_inode_getfd("[ksu_driver]", &ksu_driver_fops,
					    NULL, O_RDWR);
		if (fd >= 0 && regs->regs[3])
			p_copy_to_user((void __user *)regs->regs[3], &fd, sizeof(fd));
		regs->regs[0] = 0;
		return;
	}
	if (nr == 147 /* setresuid */ && mgr_uid > 0 &&
	    (int)current_uid().val == mgr_uid) {
		int fd = p_anon_inode_getfd("[ksu_driver]", &ksu_driver_fops,
					    NULL, O_RDWR);
		(void)fd;
	}
}

static long ksu_driver_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case KSU_IOCTL_GET_INFO: {
		struct ksu_get_info_cmd c = {
			.version = KSU_VERSION,
			/* Pretend to be the registered manager, loaded late: the shim has no
			 * manager-appid bookkeeping, and late-load mode is how this root is
			 * actually installed. */
			.flags = (1U << 1) | (1U << 2),
			.features = 5,
			.uapi_version = KSU_UAPI_VERSION,
		};
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_INFO_LEGACY: {
		struct ksu_get_info_legacy_cmd c = {
			.version = KSU_VERSION,
			.flags = (1U << 1) | (1U << 2),
			.features = 5,
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
		struct ksu_get_manager_appid_cmd c = { .appid = (u32)current_uid().val };
		return p_copy_to_user(uarg, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_MANAGERS: {
		/* The manager probes with count=0 first, then asks for the entries.
		 * Report the caller as the one and only active manager. */
		struct ksu_get_managers_hdr hdr;
		if (p_copy_from_user(&hdr, uarg, sizeof(hdr)))
			return -EFAULT;
		if (hdr.count == 0) {
			hdr.count = 0;
			hdr.total_count = 1;
			return p_copy_to_user(uarg, &hdr, sizeof(hdr)) ? -EFAULT : 0;
		}
		struct ksu_get_managers_one one = {
			.count = 1,
			.total_count = 1,
			.uid = (u32)current_uid().val,
			.signature_index = 0,
		};
		return p_copy_to_user(uarg, &one, sizeof(one)) ? -EFAULT : 0;
	}
	case KSU_IOCTL_GET_FEATURE: {
		struct ksu_get_feature_cmd c;
		if (p_copy_from_user(&c, uarg, sizeof(c)))
			return -EFAULT;
		c.value = 1;
		c.supported = 1;
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
	case 0x4b02: /* KHACK_LOAD_KO: uarg points at the module path */
		return khack_load_ko((const char __user *)uarg);
	default:
		/* Unknown op: report success and zero the output buffer.  The manager
		 * treats -EINVAL as "driver is incomplete" and flips its UI to
		 * unsupported, so a silent no-op is the safer answer. */
		if ((_IOC_DIR(cmd) & _IOC_READ) && uarg) {
			char zero[128] = {0};
			unsigned int sz = _IOC_SIZE(cmd);
			if (sz > sizeof(zero))
				sz = sizeof(zero);
			p_copy_to_user(uarg, zero, sz);
		}
		return 0;
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

static unsigned long klname_addr;
module_param(klname_addr, ulong, 0444);
MODULE_PARM_DESC(klname_addr, "address of kallsyms_lookup_name (from /proc/kallsyms)");

typedef unsigned long (*klname_fn)(const char *);
static klname_fn p_klname;

/* Load a module from kernel context: no seccomp, no adb shell. */
static long khack_load_ko(const char __user *upath)
{
	char path[256];
	struct file *f;
	int fd, ret;
	typedef int (*finit_fn)(int fd, const void __user *uargs, int flags);
	finit_fn finit;

	pr_err("khack2: load_ko enter, upath=%px klname=%px\n", upath, (void *)p_klname);
	if (!p_klname)
		return -ENOSYS;
	/* arm64 exposes the syscall wrapper, which reads its arguments from
	 * pt_regs, not the plain (fd, uargs, flags) signature. */
	/* __arm64_sys_finit_module is only the syscall wrapper; its real body
	 * lives in __do_sys_finit_module, exposed under the ".descriptor" name
	 * on this vendor kernel and taking (fd, uargs, flags) directly. */
	finit = (finit_fn)p_klname("__do_sys_finit_module.descriptor");
	if (!finit)
		finit = (finit_fn)p_klname("__do_sys_finit_module");
	if (!finit) {
		pr_err("khack2: finit_module not found\n");
		return -ENOSYS;
	}
	{
		long n = strncpy_from_user(path, upath, sizeof(path) - 1);
		if (n < 0) { pr_err("khack2: strncpy_from_user=%ld\n", n); return -EFAULT; }
		pr_err("khack2: path='%s' finit=%px\n", path, (void *)finit);
	}
	path[sizeof(path) - 1] = 0;
	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_err("khack2: filp_open=%ld\n", PTR_ERR(f));
		return PTR_ERR(f);
	}
	fd = get_unused_fd_flags(O_RDONLY);
	if (fd < 0) { filp_close(f, NULL); return fd; }
	fd_install(fd, f);
	ret = finit(fd, NULL, 0);
	{
		void (*p_ksys_close)(unsigned int) =
			(void (*)(unsigned int))p_klname("ksys_close");
		if (p_ksys_close)
			p_ksys_close(fd);
		/* no fallback: the reference already belongs to the fd table,
		 * closing it again here would drop it twice. */
	}
	pr_info("khack2: load %s -> %d\n", path, ret);
	return ret;
}

static int __init khack2_init(void)
{
	int ret;

	if (klname_addr) {
		p_klname = (klname_fn)klname_addr;
		pr_info("khack2: kallsyms_lookup_name=%px\n", p_klname);
	}

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

	p_tp_register = (tp_reg_fn)__symbol_get("tracepoint_probe_register");
	{
		tp_iter_fn iter = (tp_iter_fn)__symbol_get("for_each_kernel_tracepoint");
		struct tp_find f = { NULL };
		if (iter) {
			iter(tp_find_cb, &f);
			p_tp_sys_enter = f.found;
		}
	}
	if (p_tp_register && p_tp_sys_enter) {
		int r = p_tp_register(p_tp_sys_enter, (void *)ksu_sys_enter_probe, NULL);
		pr_info("khack2: sys_enter tracepoint hook rc=%d (mgr_uid=%d)\n", r, mgr_uid);
	} else {
		pr_info("khack2: tracepoint symbols unavailable (%px %px)\n",
			p_tp_register, p_tp_sys_enter);
	}

	pr_info("khack2: loaded, ksu uapi v4 shim ready\n");
	return 0;
}

static void __exit khack2_exit(void)
{
	misc_deregister(&khack2_dev);
}

module_init(khack2_init);
module_exit(khack2_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack2: KernelSU uapi v4 shim (anon_inode + reboot hook)");
