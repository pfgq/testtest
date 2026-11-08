// SPDX-License-Identifier: GPL-2.0
/*
 * ksu095 - KernelSU v0.9.5 (11872) LKM Driver for Linux 4.19 (No KPROBES)
 *
 * Implements full KernelSU 0.9.5 Root Management (App Profiles, Allowlist
 * persistence at /data/adb/ksu/.allowlist, Manager auto-detection) and
 * Module Loading support (ksud 0.9.5 late-init / post-fs-data / overlayfs
 * mount / Zygote module umount) using raw_syscalls:sys_enter & sys_exit
 * tracepoints.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/nsproxy.h>
#include <linux/miscdevice.h>
#include <asm/ptrace.h>
#include <asm/current.h>

/* Offset from printk to kallsyms_lookup_name on 4.19.113-perf-gec90c723c482 */
#define KALLSYMS_DELTA 0x4b228UL

/* ---- KernelSU 0.9.5 Protocol Constants & Structures ---- */
#define KERNEL_SU_VERSION 11872
#define KERNEL_SU_OPTION  0xDEADBEEFU

#define CMD_GRANT_ROOT        0
#define CMD_BECOME_MANAGER    1
#define CMD_GET_VERSION       2
#define CMD_ALLOW_SU          3
#define CMD_DENY_SU           4
#define CMD_GET_ALLOW_LIST    5
#define CMD_GET_DENY_LIST     6
#define CMD_REPORT_EVENT      7
#define CMD_SET_SEPOLICY      8
#define CMD_CHECK_SAFEMODE    9
#define CMD_GET_APP_PROFILE   10
#define CMD_SET_APP_PROFILE   11
#define CMD_UID_GRANTED_ROOT  12
#define CMD_UID_SHOULD_UMOUNT 13

/* 自定义：内核态代跑 ksys_mount，绕开调用者 seccomp（mount(2) 会被 SIGSYS 杀）
 * arg3 -> user buffer: dev[64] | dir[64] | data[64] | type[64] | flags(u64 @256)
 */
#define CMD_KSU_MOUNT         0x100
#define CMD_KSU_UMOUNT        0x101
#define KSU_MOUNT_OFF_DEV     0
#define KSU_MOUNT_OFF_DIR     64
#define KSU_MOUNT_OFF_DATA    128
#define KSU_MOUNT_OFF_TYPE    192
#define KSU_MOUNT_OFF_FLAGS   256

#define EVENT_POST_FS_DATA    1
#define EVENT_BOOT_COMPLETED  2
#define EVENT_MODULE_MOUNTED  3

#define KSU_APP_PROFILE_VER   2
#define KSU_MAX_PACKAGE_NAME  256
#define KSU_MAX_GROUPS        32
#define KSU_SELINUX_DOMAIN    64

#define FILE_MAGIC            0x7f4b5355U
#define FILE_FORMAT_VERSION   3U
#define KERNEL_SU_ALLOWLIST   "/data/adb/ksu/.allowlist"
#define KSUD_PATH             "/data/adb/ksud"
#define SU_PATH               "/system/bin/su"
#define SH_PATH               "/system/bin/sh"
#define KSU_DEFAULT_SELINUX_DOMAIN "u:r:su:s0"

#define KSU_INVALID_UID       ((uid_t)-1)

struct root_profile {
	s32 uid;
	s32 gid;
	s32 groups_count;
	s32 groups[KSU_MAX_GROUPS];
	struct {
		u64 effective;
		u64 permitted;
		u64 inheritable;
	} capabilities;
	char selinux_domain[KSU_SELINUX_DOMAIN];
	s32 namespaces;
};

struct non_root_profile {
	bool umount_modules;
};

struct app_profile {
	u32 version;
	char key[KSU_MAX_PACKAGE_NAME];
	s32 current_uid;
	bool allow_su;
	union {
		struct {
			bool use_default;
			char template_name[KSU_MAX_PACKAGE_NAME];
			struct root_profile profile;
		} rp_config;
		struct {
			bool use_default;
			struct non_root_profile profile;
		} nrp_config;
	};
};

struct task_security_struct {
	u32 osid;
	u32 sid;
	u32 exec_sid;
	u32 create_sid;
	u32 keycreate_sid;
	u32 sockcreate_sid;
};

/* ---- Dynamically Resolved Kernel Symbols ---- */
typedef unsigned long (*klname_fn)(const char *name);
typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);
typedef long (*strncpy_user_fn)(char *dst, const char __user *src, long count);
typedef struct file *(*filp_open_fn)(const char *filename, int flags, umode_t mode);
typedef int (*filp_close_fn)(struct file *filp, fl_owner_t id);
typedef ssize_t (*kernel_read_fn)(struct file *file, void *buf, size_t count, loff_t *pos);
typedef ssize_t (*kernel_write_fn)(struct file *file, const void *buf, size_t count, loff_t *pos);
typedef int (*kern_path_fn)(const char *name, unsigned int flags, struct path *path);
typedef void (*path_put_fn)(const struct path *path);
typedef struct cred *(*prepare_creds_fn)(void);
typedef int (*commit_creds_fn)(struct cred *new);
typedef const struct cred *(*override_creds_fn)(const struct cred *new);
typedef void (*revert_creds_fn)(const struct cred *old);
typedef struct group_info *(*groups_alloc_fn)(int gidsetsize);
typedef void (*groups_free_fn)(struct group_info *group_info);
typedef int (*set_groups_fn)(struct cred *new, struct group_info *group_info);
typedef int (*secctx_to_secid_fn)(const char *secdata, u32 seclen, u32 *secid);
typedef int (*secid_to_secctx_fn)(u32 secid, char **secdata, u32 *seclen);
typedef void (*release_secctx_fn)(char *secdata, u32 seclen);
typedef int (*ksys_umount_fn)(char __user *name, int flags);
typedef long (*ksys_mount_fn)(char __user *dev_name, char __user *dir_name,
			      char __user *type, unsigned long flags,
			      void __user *data);
typedef int (*tp_reg_fn)(void *tp, void *probe, void *data);
typedef int (*tp_unreg_fn)(void *tp, void *probe, void *data);
typedef void (*tp_sync_fn)(void);
typedef bool (*queue_work_on_fn)(int cpu, struct workqueue_struct *wq, struct work_struct *work);
typedef bool (*flush_work_fn)(struct work_struct *work);
typedef void *(*sidtab_search_fn)(void *sidtab, u32 sid);
typedef int (*ebitmap_set_bit_fn)(void *e, u32 bit, int value);

static klname_fn          p_klname;
static copy_fn            p_copy_to_user;
static copy_fn            p_copy_from_user;
static strncpy_user_fn    p_strncpy_from_user;
static filp_open_fn       p_filp_open;
static filp_close_fn      p_filp_close;
static kernel_read_fn     p_kernel_read;
static kernel_write_fn    p_kernel_write;
static kern_path_fn       p_kern_path;
static path_put_fn        p_path_put;
static prepare_creds_fn   p_prepare_creds;
static commit_creds_fn    p_commit_creds;
static override_creds_fn  p_override_creds;
static revert_creds_fn    p_revert_creds;
static groups_alloc_fn    p_groups_alloc;
static groups_free_fn     p_groups_free;
static set_groups_fn      p_set_groups;
static secctx_to_secid_fn p_secctx_to_secid;
static secid_to_secctx_fn p_secid_to_secctx;
static release_secctx_fn  p_release_secctx;
static ksys_umount_fn     p_ksys_umount;
static ksys_mount_fn      p_ksys_mount;
static tp_reg_fn          p_tp_reg;
static tp_unreg_fn        p_tp_unreg;
static tp_sync_fn         p_tp_sync;
static queue_work_on_fn   p_queue_work_on;
static flush_work_fn      p_flush_work;

static void *p_tp_sys_enter;
static void *p_tp_sys_exit;
static struct workqueue_struct **p_system_wq;
static struct task_struct *p_init_task;

/* ---- Local String & Memory Helpers (Zero external CRC dependencies) ---- */
static size_t k_strlen(const char *s)
{
	size_t n = 0;
	if (!s)
		return 0;
	while (s[n])
		n++;
	return n;
}

static int k_strcmp(const char *a, const char *b)
{
	while (*a && *a == *b) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

static int k_strncmp(const char *a, const char *b, size_t n)
{
	if (!n)
		return 0;
	while (--n && *a && *a == *b) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

static char *k_strcpy(char *dst, const char *src)
{
	char *d = dst;
	while ((*d++ = *src++) != '\0')
		;
	return dst;
}

static void *k_memset(void *s, int c, size_t n)
{
	u8 *p = (u8 *)s;
	while (n--)
		*p++ = (u8)c;
	return s;
}

static void *k_memcpy(void *dst, const void *src, size_t n)
{
	u8 *d = (u8 *)dst;
	const u8 *s = (const u8 *)src;
	while (n--)
		*d++ = *s++;
	return dst;
}

static int k_memcmp(const void *s1, const void *s2, size_t n)
{
	const u8 *p1 = (const u8 *)s1;
	const u8 *p2 = (const u8 *)s2;
	while (n--) {
		if (*p1 != *p2)
			return *p1 - *p2;
		p1++;
		p2++;
	}
	return 0;
}

/* ---- Profile & Allowlist Storage ---- */
#define MAX_PROFILES 256

struct profile_slot {
	bool used;
	struct app_profile profile;
};

static struct profile_slot g_profiles[MAX_PROFILES];
static struct root_profile default_root_profile;
static struct non_root_profile default_non_root_profile;
static DEFINE_SPINLOCK(profile_lock);

static uid_t ksu_manager_uid = KSU_INVALID_UID;
static bool ksu_module_mounted = false;
static bool tp_enter_registered = false;
static bool tp_exit_registered = false;

static struct work_struct ksu_save_work;
static struct work_struct ksu_load_work;

static void init_default_profiles(void)
{
	default_root_profile.uid = 0;
	default_root_profile.gid = 0;
	default_root_profile.groups_count = 1;
	default_root_profile.groups[0] = 0;
	k_memset(&default_root_profile.capabilities, 0xff,
		 sizeof(default_root_profile.capabilities));
	default_root_profile.namespaces = 0;
	k_strcpy(default_root_profile.selinux_domain, KSU_DEFAULT_SELINUX_DOMAIN);

	default_non_root_profile.umount_modules = true;
}

/*
 * Vendor 4.19.113 kernel has extra vendor fields in struct task_struct
 * (CONFIG_MIHW, CONFIG_PACKAGE_RUNTIME_INFO, CONFIG_PERF_HUMANTASK),
 * shifting task_struct->cred from 0x7c0 to 0x7c8 (1992).
 */
static inline const struct cred *get_task_cred_safe(void)
{
	unsigned long tsk = (unsigned long)current;
	const struct cred *c = *(const struct cred **)(tsk + 1992);
	return c;
}

static inline uid_t get_current_uid_val(void)
{
	const struct cred *c = get_task_cred_safe();
	if (unlikely(!c || (unsigned long)c < PAGE_OFFSET))
		return KSU_INVALID_UID;
	return c->uid.val;
}

static inline bool is_manager(void)
{
	uid_t cur = get_current_uid_val();
	if (ksu_manager_uid == KSU_INVALID_UID || cur == KSU_INVALID_UID)
		return false;
	return ksu_manager_uid == cur || (cur % 100000) == (ksu_manager_uid % 100000);
}

static void detect_manager_uid_by_path(const char *path_str)
{
	struct path path;
	if (!p_kern_path || !p_path_put)
		return;
	if (p_kern_path(path_str, 0, &path) == 0) {
		if (path.dentry && path.dentry->d_inode) {
			uid_t uid = path.dentry->d_inode->i_uid.val;
			if (uid >= 10000) {
				ksu_manager_uid = uid;
				printk(KERN_INFO "ksu095: detected manager uid=%u (%s)\n",
				       uid, path_str);
			}
		}
		p_path_put(&path);
	}
}

static bool forbid_system_uid(uid_t uid)
{
	return uid < 2000 && uid != 1000;
}

static bool is_ksu_domain(void)
{
	const struct cred *c = get_task_cred_safe();
	const struct task_security_struct *tsec;
	char *domain = NULL;
	u32 seclen = 0;
	bool res = false;

	if (!c || (unsigned long)c < PAGE_OFFSET)
		return false;
	tsec = (const struct task_security_struct *)c->security;
	if (!tsec)
		return false;
	if (tsec->sid == 1) /* SECINITSID_KERNEL */
		return true;
	if (p_secid_to_secctx && p_release_secctx) {
		if (p_secid_to_secctx(tsec->sid, &domain, &seclen) == 0 && domain) {
			if (seclen == k_strlen(KSU_DEFAULT_SELINUX_DOMAIN) &&
			    k_strncmp(KSU_DEFAULT_SELINUX_DOMAIN, domain, seclen) == 0)
				res = true;
			p_release_secctx(domain, seclen);
		}
	}
	return res;
}

static bool ksu_is_allow_uid(uid_t uid)
{
	int i;
	unsigned long flags;
	bool allowed = false;

	if (unlikely(uid == 0))
		return true;

	if (forbid_system_uid(uid))
		return false;

	if (ksu_manager_uid != KSU_INVALID_UID &&
	    (ksu_manager_uid == uid || (uid % 100000) == (ksu_manager_uid % 100000)))
		return true;

	spin_lock_irqsave(&profile_lock, flags);
	for (i = 0; i < MAX_PROFILES; i++) {
		if (g_profiles[i].used &&
		    (uid_t)g_profiles[i].profile.current_uid == uid) {
			allowed = g_profiles[i].profile.allow_su;
			break;
		}
	}
	spin_unlock_irqrestore(&profile_lock, flags);
	return allowed;
}

static bool ksu_get_app_profile(struct app_profile *profile)
{
	int i;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&profile_lock, flags);
	for (i = 0; i < MAX_PROFILES; i++) {
		if (g_profiles[i].used &&
		    g_profiles[i].profile.current_uid == profile->current_uid) {
			k_memcpy(profile, &g_profiles[i].profile, sizeof(*profile));
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&profile_lock, flags);
	return found;
}

static void queue_save_allowlist(void)
{
	if (p_queue_work_on && p_system_wq && *p_system_wq)
		p_queue_work_on(WORK_CPU_UNBOUND, *p_system_wq, &ksu_save_work);
}

static void queue_load_allowlist(void)
{
	if (p_queue_work_on && p_system_wq && *p_system_wq)
		p_queue_work_on(WORK_CPU_UNBOUND, *p_system_wq, &ksu_load_work);
}

static bool ksu_set_app_profile(const struct app_profile *profile, bool persist)
{
	int i, free_idx = -1;
	unsigned long flags;

	if (!profile)
		return false;
	if (forbid_system_uid(profile->current_uid) &&
	    k_strcmp(profile->key, "#") != 0 &&
	    k_strcmp(profile->key, "$") != 0)
		return false;

	spin_lock_irqsave(&profile_lock, flags);
	for (i = 0; i < MAX_PROFILES; i++) {
		if (g_profiles[i].used) {
			if (g_profiles[i].profile.current_uid == profile->current_uid &&
			    k_strcmp(g_profiles[i].profile.key, profile->key) == 0) {
				k_memcpy(&g_profiles[i].profile, profile, sizeof(*profile));
				free_idx = i;
				break;
			}
		} else if (free_idx < 0) {
			free_idx = i;
		}
	}

	if (free_idx >= 0 && !g_profiles[free_idx].used) {
		g_profiles[free_idx].used = true;
		k_memcpy(&g_profiles[free_idx].profile, profile, sizeof(*profile));
	}

	if (k_strcmp(profile->key, "$") == 0) {
		k_memcpy(&default_non_root_profile, &profile->nrp_config.profile,
			 sizeof(default_non_root_profile));
	}
	if (k_strcmp(profile->key, "#") == 0) {
		k_memcpy(&default_root_profile, &profile->rp_config.profile,
			 sizeof(default_root_profile));
	}
	spin_unlock_irqrestore(&profile_lock, flags);

	if (free_idx < 0)
		return false;

	if (persist)
		queue_save_allowlist();

	return true;
}

static bool ksu_uid_should_umount(uid_t uid)
{
	struct app_profile profile;

	if (ksu_manager_uid != KSU_INVALID_UID &&
	    (ksu_manager_uid == uid || (uid % 100000) == (ksu_manager_uid % 100000)))
		return false;

	k_memset(&profile, 0, sizeof(profile));
	profile.current_uid = uid;
	if (!ksu_get_app_profile(&profile))
		return default_non_root_profile.umount_modules;

	if (profile.allow_su)
		return false;

	if (profile.nrp_config.use_default)
		return default_non_root_profile.umount_modules;
	return profile.nrp_config.profile.umount_modules;
}

static void ksu_get_root_profile(uid_t uid, struct root_profile *out)
{
	int i;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&profile_lock, flags);
	for (i = 0; i < MAX_PROFILES; i++) {
		if (g_profiles[i].used &&
		    (uid_t)g_profiles[i].profile.current_uid == uid &&
		    g_profiles[i].profile.allow_su) {
			if (!g_profiles[i].profile.rp_config.use_default) {
				k_memcpy(out, &g_profiles[i].profile.rp_config.profile,
					 sizeof(*out));
				found = true;
			}
			break;
		}
	}
	if (!found)
		k_memcpy(out, &default_root_profile, sizeof(*out));
	spin_unlock_irqrestore(&profile_lock, flags);
}

static bool ksu_get_allow_list(u32 *array, u32 *length, bool allow)
{
	int i;
	u32 cnt = 0;
	unsigned long flags;

	spin_lock_irqsave(&profile_lock, flags);
	for (i = 0; i < MAX_PROFILES && cnt < 128; i++) {
		if (g_profiles[i].used &&
		    g_profiles[i].profile.allow_su == allow &&
		    g_profiles[i].profile.current_uid >= 2000 &&
		    k_strcmp(g_profiles[i].profile.key, "#") != 0 &&
		    k_strcmp(g_profiles[i].profile.key, "$") != 0) {
			array[cnt++] = (u32)g_profiles[i].profile.current_uid;
		}
	}
	spin_unlock_irqrestore(&profile_lock, flags);
	*length = cnt;
	return true;
}

/* ---- Persistence Workqueue Handlers ---- */
static void do_save_allow_list(struct work_struct *work)
{
	u32 magic = FILE_MAGIC;
	u32 version = FILE_FORMAT_VERSION;
	loff_t off = 0;
	struct file *fp;
	int i;

	if (!p_filp_open || !p_kernel_write || !p_filp_close)
		return;

	fp = p_filp_open(KERNEL_SU_ALLOWLIST, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(fp)) {
		printk(KERN_ERR "ksu095: save_allow_list open failed: %ld\n", PTR_ERR(fp));
		return;
	}

	if (p_kernel_write(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
	    p_kernel_write(fp, &version, sizeof(version), &off) != sizeof(version)) {
		printk(KERN_ERR "ksu095: save_allow_list header write failed\n");
		p_filp_close(fp, NULL);
		return;
	}

	for (i = 0; i < MAX_PROFILES; i++) {
		struct app_profile snap;
		bool used = false;
		unsigned long flags;

		spin_lock_irqsave(&profile_lock, flags);
		if (g_profiles[i].used) {
			used = true;
			k_memcpy(&snap, &g_profiles[i].profile, sizeof(snap));
		}
		spin_unlock_irqrestore(&profile_lock, flags);

		if (used)
			p_kernel_write(fp, &snap, sizeof(snap), &off);
	}

	p_filp_close(fp, NULL);
	printk(KERN_INFO "ksu095: saved allowlist to %s\n", KERNEL_SU_ALLOWLIST);
}

static void do_load_allow_list(struct work_struct *work)
{
	loff_t off = 0;
	ssize_t ret;
	struct file *fp;
	u32 magic = 0, version = 0;
	int count = 0;

	if (!p_filp_open || !p_kernel_read || !p_filp_close)
		return;

	fp = p_filp_open(KERNEL_SU_ALLOWLIST, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		printk(KERN_INFO "ksu095: no existing allowlist (%ld)\n", PTR_ERR(fp));
		return;
	}

	if (p_kernel_read(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
	    magic != FILE_MAGIC) {
		printk(KERN_ERR "ksu095: invalid allowlist magic: 0x%x\n", magic);
		p_filp_close(fp, NULL);
		return;
	}

	if (p_kernel_read(fp, &version, sizeof(version), &off) != sizeof(version)) {
		p_filp_close(fp, NULL);
		return;
	}

	while (count < MAX_PROFILES) {
		struct app_profile prof;
		ret = p_kernel_read(fp, &prof, sizeof(prof), &off);
		if (ret != sizeof(prof))
			break;
		ksu_set_app_profile(&prof, false);
		count++;
	}

	p_filp_close(fp, NULL);
	printk(KERN_INFO "ksu095: loaded %d profiles from allowlist (ver=%u)\n",
	       count, version);
}

/* ---- Privilege Escalation (escape_to_root) ---- */
static void setup_selinux_domain(struct cred *cred, const char *domain)
{
	struct task_security_struct *tsec;
	u32 sid = 0;

	if (!cred || !cred->security)
		return;
	tsec = (struct task_security_struct *)cred->security;

	if (domain && domain[0] && p_secctx_to_secid) {
		if (p_secctx_to_secid(domain, k_strlen(domain), &sid) == 0 && sid != 0) {
			tsec->sid = sid;
			tsec->create_sid = 0;
			tsec->keycreate_sid = 0;
			tsec->sockcreate_sid = 0;
			return;
		}
	}
	/* Fallback to SECINITSID_KERNEL (1) if u:r:su:s0 is not in policy yet */
	tsec->sid = 1;
	tsec->create_sid = 0;
	tsec->keycreate_sid = 0;
	tsec->sockcreate_sid = 0;
}

static void escape_to_root(void)
{
	struct cred *cred;
	struct root_profile profile;
	u64 cap_for_ksud;
	uid_t orig_uid;

	if (!p_prepare_creds || !p_commit_creds)
		return;

	cred = p_prepare_creds();
	if (!cred)
		return;

	orig_uid = cred->uid.val;
	if (cred->euid.val == 0) {
		setup_selinux_domain(cred, KSU_DEFAULT_SELINUX_DOMAIN);
		p_commit_creds(cred);
		return;
	}

	ksu_get_root_profile(orig_uid, &profile);

	cred->uid.val   = profile.uid;
	cred->suid.val  = profile.uid;
	cred->euid.val  = profile.uid;
	cred->fsuid.val = profile.uid;

	cred->gid.val   = profile.gid;
	cred->fsgid.val = profile.gid;
	cred->sgid.val  = profile.gid;
	cred->egid.val  = profile.gid;

	cap_for_ksud = profile.capabilities.effective | (1ULL << CAP_DAC_READ_SEARCH);
	k_memcpy(&cred->cap_effective, &cap_for_ksud, sizeof(cred->cap_effective));
	k_memcpy(&cred->cap_inheritable, &profile.capabilities.effective,
		 sizeof(cred->cap_inheritable));
	k_memcpy(&cred->cap_permitted, &profile.capabilities.effective,
		 sizeof(cred->cap_permitted));
	k_memcpy(&cred->cap_bset, &profile.capabilities.effective,
		 sizeof(cred->cap_bset));
	k_memcpy(&cred->cap_ambient, &profile.capabilities.effective,
		 sizeof(cred->cap_ambient));

	/* Disable TIF_SECCOMP flag on thread_info (offset 0 of task_struct) */
	current_thread_info()->flags &= ~(TIF_SECCOMP | _TIF_SECCOMP);

	if (profile.groups_count > 0 && profile.groups_count <= KSU_MAX_GROUPS &&
	    p_groups_alloc && p_set_groups) {
		struct group_info *gi = p_groups_alloc(profile.groups_count);
		if (gi) {
			int i;
			for (i = 0; i < profile.groups_count; i++)
				gi->gid[i].val = profile.groups[i];
			p_set_groups(cred, gi);
			atomic_dec(&gi->usage);
		}
	}

	setup_selinux_domain(cred, profile.selinux_domain);
	p_commit_creds(cred);
}

/* ---- Userspace Stack Helper ---- */
static void __user *userspace_stack_buffer(struct pt_regs *regs, const void *d, size_t len)
{
	char __user *p;
	if (!regs || !regs->sp || !p_copy_to_user)
		return NULL;
	p = (char __user *)(regs->sp - len);
	return p_copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(struct pt_regs *regs)
{
	static const char sh_path[] = SH_PATH;
	return userspace_stack_buffer(regs, sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(struct pt_regs *regs)
{
	static const char ksud_path[] = KSUD_PATH;
	return userspace_stack_buffer(regs, ksud_path, sizeof(ksud_path));
}

static long safe_strncpy_from_user(char *dst, const char __user *src, long count)
{
	if (unlikely(count <= 0 || !src || !p_strncpy_from_user))
		return -EFAULT;

	return p_strncpy_from_user(dst, src, count);
}

/* ---- Zygote OverlayFS Umount Support ---- */
static bool should_umount_path(struct path *path)
{
	if (!path)
		return false;
	if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
		const char *fstype = path->mnt->mnt_sb->s_type->name;
		if (fstype && k_strcmp(fstype, "overlay") == 0)
			return true;
	}
	return false;
}

static void try_umount(struct pt_regs *regs, const char *mnt, bool check_mnt, int flags)
{
	struct path path;
	char __user *umnt;

	if (!p_kern_path || !p_path_put || !p_ksys_umount)
		return;
	if (p_kern_path(mnt, 0, &path) != 0)
		return;
	if (path.dentry != path.mnt->mnt_root) {
		p_path_put(&path);
		return;
	}
	if (check_mnt && !should_umount_path(&path)) {
		p_path_put(&path);
		return;
	}
	p_path_put(&path);

	umnt = (char __user *)userspace_stack_buffer(regs, mnt, k_strlen(mnt) + 1);
	if (umnt)
		p_ksys_umount(umnt, flags);
}

/* ---- KSU 0.9.5 prctl Handler ---- */
static void ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
			     unsigned long arg4, unsigned long arg5)
{
	void __user *result = (void __user *)arg5;
	u32 reply_ok = KERNEL_SU_OPTION;
	uid_t cur_uid;
	bool from_root, from_manager;

	if ((u32)option != KERNEL_SU_OPTION)
		return;

	cur_uid = get_current_uid_val();
	if (cur_uid == KSU_INVALID_UID)
		return;
	if (ksu_manager_uid != KSU_INVALID_UID &&
	    cur_uid != ksu_manager_uid &&
	    (cur_uid % 100000) == (ksu_manager_uid % 100000)) {
		ksu_manager_uid = cur_uid;
	}

	/* Auto-check if caller is CMD_BECOME_MANAGER before manager is known */
	if (arg2 == CMD_BECOME_MANAGER && arg3) {
		char param[128];
		k_memset(param, 0, sizeof(param));
		if (safe_strncpy_from_user(param, (const char __user *)arg3,
					   sizeof(param) - 1) > 0) {
			/* Verify caller owns this directory or package is me.weishu.kernelsu */
			struct path path;
			if (p_kern_path && p_path_put &&
			    p_kern_path(param, 0, &path) == 0) {
				uid_t dir_uid = KSU_INVALID_UID;
				if (path.dentry && path.dentry->d_inode)
					dir_uid = path.dentry->d_inode->i_uid.val;
				p_path_put(&path);
				if (dir_uid == cur_uid &&
				    (ksu_manager_uid == KSU_INVALID_UID ||
				     (cur_uid % 100000) == (ksu_manager_uid % 100000) ||
				     k_strncmp(param, "/data/data/me.weishu.kernelsu", 29) == 0 ||
				     k_strncmp(param, "/data/user/", 11) == 0)) {
					ksu_manager_uid = cur_uid;
				}
			}
		}
	}

	from_root = (cur_uid == 0);
	from_manager = is_manager();

	if (!from_root && !from_manager && !ksu_is_allow_uid(cur_uid))
		return;

	if (arg2 == CMD_BECOME_MANAGER) {
		if (from_manager && result)
			p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		return;
	}

	/* 说明：mount/umount 不能在这里做 —— sys_enter tracepoint 上下文是原子的，
	 * ksys_mount() 会睡，实测直接 "scheduling while atomic" + kernel panic。
	 * 改走 /dev/ksu095 的 ioctl（进程上下文）。
	 */

	if (arg2 == CMD_GRANT_ROOT) {
		if (from_root || from_manager || ksu_is_allow_uid(cur_uid)) {
			escape_to_root();
			if (result)
				p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
		return;
	}

	if (arg2 == CMD_GET_VERSION) {
		u32 ver = KERNEL_SU_VERSION;
		u32 is_lkm = 1;
		if (arg3)
			p_copy_to_user((void __user *)arg3, &ver, sizeof(ver));
		if (arg4)
			p_copy_to_user((void __user *)arg4, &is_lkm, sizeof(is_lkm));
		if (result)
			p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		return;
	}

	if (arg2 == CMD_REPORT_EVENT) {
		if (!from_root)
			return;
		switch (arg3) {
		case EVENT_POST_FS_DATA:
			printk(KERN_INFO "ksu095: EVENT_POST_FS_DATA\n");
			queue_load_allowlist();
			break;
		case EVENT_BOOT_COMPLETED:
			printk(KERN_INFO "ksu095: EVENT_BOOT_COMPLETED\n");
			if (ksu_manager_uid == KSU_INVALID_UID)
				detect_manager_uid_by_path("/data/data/me.weishu.kernelsu");
			break;
		case EVENT_MODULE_MOUNTED:
			ksu_module_mounted = true;
			printk(KERN_INFO "ksu095: EVENT_MODULE_MOUNTED\n");
			break;
		default:
			break;
		}
		if (result)
			p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		return;
	}

	if (arg2 == CMD_SET_SEPOLICY) {
		if (!from_root)
			return;
		/* SELinux is already permissive via khack_dl; acknowledge sepolicy load */
		if (result)
			p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		return;
	}

	if (arg2 == CMD_CHECK_SAFEMODE) {
		/*
		 * CRITICAL: In KSU 0.9.5, writing reply_ok (0xDEADBEEF) to result
		 * means safe mode IS active! Leave result untouched for normal mode.
		 */
		return;
	}

	if (arg2 == CMD_GET_ALLOW_LIST || arg2 == CMD_GET_DENY_LIST) {
		u32 array[128];
		u32 array_length = 0;
		bool success = ksu_get_allow_list(array, &array_length,
						  arg2 == CMD_GET_ALLOW_LIST);
		if (success && arg3 && arg4) {
			if (!p_copy_to_user((void __user *)arg4, &array_length,
					    sizeof(array_length)) &&
			    !p_copy_to_user((void __user *)arg3, array,
					    sizeof(u32) * array_length)) {
				if (result)
					p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
			}
		}
		return;
	}

	if (arg2 == CMD_UID_GRANTED_ROOT || arg2 == CMD_UID_SHOULD_UMOUNT) {
		uid_t target_uid = (uid_t)arg3;
		bool allow = false;
		if (arg2 == CMD_UID_GRANTED_ROOT)
			allow = ksu_is_allow_uid(target_uid);
		else
			allow = ksu_uid_should_umount(target_uid);

		if (arg4 && !p_copy_to_user((void __user *)arg4, &allow, sizeof(allow))) {
			if (result)
				p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
		return;
	}

	if (!from_manager && !from_root)
		return;

	if (arg2 == CMD_GET_APP_PROFILE) {
		struct app_profile profile;
		if (!arg3 || p_copy_from_user(&profile, (void __user *)arg3, sizeof(profile)))
			return;
		if (ksu_get_app_profile(&profile)) {
			if (!p_copy_to_user((void __user *)arg3, &profile, sizeof(profile))) {
				if (result)
					p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
			}
		}
		return;
	}

	if (arg2 == CMD_SET_APP_PROFILE) {
		struct app_profile profile;
		if (!arg3 || p_copy_from_user(&profile, (void __user *)arg3, sizeof(profile)))
			return;
		if (ksu_set_app_profile(&profile, true)) {
			if (result)
				p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
		return;
	}

	if (arg2 == CMD_ALLOW_SU || arg2 == CMD_DENY_SU) {
		/* Legacy fallback */
		struct app_profile profile;
		u32 target_uid = 0;
		if (arg3 && !p_copy_from_user(&target_uid, (void __user *)arg3, sizeof(target_uid))) {
			k_memset(&profile, 0, sizeof(profile));
			profile.version = KSU_APP_PROFILE_VER;
			profile.current_uid = target_uid;
			profile.allow_su = (arg2 == CMD_ALLOW_SU);
			profile.rp_config.use_default = true;
			profile.nrp_config.use_default = true;
			k_strcpy(profile.key, "legacy");
			ksu_set_app_profile(&profile, true);
			if (result)
				p_copy_to_user(result, &reply_ok, sizeof(reply_ok));
		}
		return;
	}
}

/* ---- Syscall Tracepoint Probes ---- */
#define NR_FACCESSAT 48
#define NR_NEWFSTATAT 79
#define NR_SETUID    146
#define NR_SETRESUID 147
#define NR_PRCTL     167
#define NR_EXECVE    221
#define NR_EXECVEAT  281

static void ksu_sys_enter_probe(void *ignore, struct pt_regs *regs, long id)
{
	if (unlikely(!regs || !p_copy_to_user))
		return;

	/* 1. prctl(0xDEADBEEF, ...) */
	if (id == NR_PRCTL) {
		if ((u32)regs->regs[0] == KERNEL_SU_OPTION) {
			ksu_handle_prctl((int)regs->regs[0], regs->regs[1],
					 regs->regs[2], regs->regs[3],
					 regs->regs[4]);
		}
		return;
	}

	/* 2. sucompat: faccessat & newfstatat */
	if (id == NR_FACCESSAT || id == NR_NEWFSTATAT) {
		const char __user *ufn = (const char __user *)regs->regs[1];
		char path[16];
		uid_t cur_uid = get_current_uid_val();

		if (!ufn || cur_uid == KSU_INVALID_UID || !ksu_is_allow_uid(cur_uid))
			return;
		k_memset(path, 0, sizeof(path));
		if (safe_strncpy_from_user(path, ufn, sizeof(path)) > 0) {
			if (k_memcmp(path, SU_PATH, sizeof(SU_PATH)) == 0) {
				char __user *sh = sh_user_path(regs);
				if (sh)
					regs->regs[1] = (unsigned long)sh;
			}
		}
		return;
	}

	/* 3. sucompat: execve & execveat */
	if (id == NR_EXECVE || id == NR_EXECVEAT) {
		int reg_idx = (id == NR_EXECVE) ? 0 : 1;
		const char __user *ufn = (const char __user *)regs->regs[reg_idx];
		char path[16];
		uid_t cur_uid = get_current_uid_val();

		if (!ufn || cur_uid == KSU_INVALID_UID || !ksu_is_allow_uid(cur_uid))
			return;
		k_memset(path, 0, sizeof(path));
		if (safe_strncpy_from_user(path, ufn, sizeof(path)) > 0) {
			if (k_memcmp(path, SU_PATH, sizeof(SU_PATH)) == 0 ||
			    k_memcmp(path, "su", 3) == 0) {
				char __user *ksud = ksud_user_path(regs);
				if (ksud) {
					regs->regs[reg_idx] = (unsigned long)ksud;
					escape_to_root();
				}
			}
		}
		return;
	}
}

static bool is_zygote_domain(void)
{
	const struct cred *c = get_task_cred_safe();
	const struct task_security_struct *tsec;
	char *domain = NULL;
	u32 seclen = 0;
	bool res = false;

	if (!c || (unsigned long)c < PAGE_OFFSET)
		return false;
	tsec = (const struct task_security_struct *)c->security;
	if (!tsec || !p_secid_to_secctx || !p_release_secctx)
		return false;
	if (p_secid_to_secctx(tsec->sid, &domain, &seclen) == 0 && domain) {
		if (seclen == 13 && k_strncmp("u:r:zygote:s0", domain, 13) == 0)
			res = true;
		p_release_secctx(domain, seclen);
	}
	return res;
}

static void ksu_sys_exit_probe(void *ignore, struct pt_regs *regs, long ret)
{
	long id;
	uid_t new_uid, appid;

	if (unlikely(!ksu_module_mounted || !regs || ret != 0))
		return;

	id = regs->syscallno;
	if (id != NR_SETRESUID && id != NR_SETUID)
		return;

	new_uid = get_current_uid_val();
	if (new_uid == KSU_INVALID_UID)
		return;

	appid = new_uid % 100000;
	if (appid < 10000 || appid > 19999)
		return;

	if (ksu_is_allow_uid(new_uid))
		return;

	if (!ksu_uid_should_umount(new_uid))
		return;

	/* Only unmount if in zygote domain (before setcon to untrusted_app) */
	if (!is_zygote_domain())
		return;

	try_umount(regs, "/system", true, 0);
	try_umount(regs, "/vendor", true, 0);
	try_umount(regs, "/product", true, 0);
	try_umount(regs, "/system_ext", true, 0);
	try_umount(regs, "/odm", true, 0);
	try_umount(regs, "/data/adb/modules", false, MNT_DETACH);
}

/* ---- Module Init & Exit ---- */
/* ---- /dev/ksu095 : 进程上下文的 mount/umount 通道 ----
 * 不能放在 prctl/tracepoint 里：那里是原子上下文，ksys_mount 会睡。
 */
#define KSU095_IOC_MOUNT  0x100
#define KSU095_IOC_UMOUNT 0x101

static long ksu095_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	char __user *base = (char __user *)arg;
	u64 mflags = 0;
	long ret;

	if (get_current_uid_val() != 0)
		return -EPERM;

	if (cmd == KSU095_IOC_MOUNT) {
		if (!base || !p_ksys_mount)
			return -EINVAL;
		if (p_copy_from_user &&
		    p_copy_from_user(&mflags, base + KSU_MOUNT_OFF_FLAGS, sizeof(mflags)))
			return -EFAULT;
		ret = p_ksys_mount(base + KSU_MOUNT_OFF_DEV,
				   base + KSU_MOUNT_OFF_DIR,
				   base + KSU_MOUNT_OFF_TYPE,
				   (unsigned long)mflags,
				   base + KSU_MOUNT_OFF_DATA);
		if (ret)
			printk(KERN_INFO "ksu095: ksys_mount -> %ld\n", ret);
		return ret;
	}

	if (cmd == KSU095_IOC_UMOUNT) {
		if (!base || !p_ksys_umount)
			return -EINVAL;
		ret = p_ksys_umount(base, 0);
		if (ret)
			printk(KERN_INFO "ksu095: ksys_umount -> %ld\n", ret);
		return ret;
	}

	return -EINVAL;
}

static const struct file_operations ksu095_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = ksu095_ioctl,
};

static struct miscdevice ksu095_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "ksu095",
	.fops  = &ksu095_fops,
	.mode  = 0666,
};


/* ---- per-domain permissive: 把 su 的 type 加进 policydb->permissive_map ----
 * 偏移来自 vmlinux.elf 反汇编（security_compute_av）：
 *   state->ss = +0x18, &ss->policydb = +0x08,
 *   policydb->permissive_map = +0x1c0, context->type = +0x08
 */
static void setup_su_permissive(void)
{
	unsigned long st;
	void *ss, *sidtab, *ctx, *pmap;
	sidtab_search_fn sidtab_search;
	ebitmap_set_bit_fn set_bit;
	u32 sid = 0, type;

	if (!p_secctx_to_secid)
		return;
	st = (unsigned long)p_klname("selinux_state");
	if (!st)
		return;
	if (p_secctx_to_secid(KSU_DEFAULT_SELINUX_DOMAIN,
			      k_strlen(KSU_DEFAULT_SELINUX_DOMAIN), &sid) != 0 || !sid)
		return;
	ss = *(void **)(st + 0x18);
	if (!ss || (unsigned long)ss < 0xffff000000000000UL)
		return;
	sidtab = *(void **)((char *)ss + 0x00);
	pmap = (char *)ss + 0x08 + 0x1c0;
	sidtab_search = (sidtab_search_fn)p_klname("sidtab_search");
	set_bit = (ebitmap_set_bit_fn)p_klname("ebitmap_set_bit");
	if (!sidtab_search || !set_bit)
		return;
	ctx = sidtab_search(sidtab, sid);
	if (!ctx)
		return;
	type = *(u32 *)((char *)ctx + 0x08);      /* context->type */
	if (!type || type > 100000)
		return;
	if (set_bit(pmap, type, 1) == 0)
		printk(KERN_INFO "ksu095: su type %u -> permissive_map\n", type);
	else
		printk(KERN_ERR "ksu095: permissive_map set failed\n");
}

static int __init ksu095_init(void)
{
	unsigned long pk = (unsigned long)__symbol_get("printk");
	int rc;

	if (!pk)
		return -ENOENT;

	p_klname = (klname_fn)(pk + KALLSYMS_DELTA);

	p_copy_to_user      = (copy_fn)p_klname("__arch_copy_to_user");
	p_copy_from_user    = (copy_fn)p_klname("__arch_copy_from_user");
	p_strncpy_from_user = (strncpy_user_fn)p_klname("strncpy_from_user");
	p_filp_open         = (filp_open_fn)p_klname("filp_open");
	p_filp_close        = (filp_close_fn)p_klname("filp_close");
	p_kernel_read       = (kernel_read_fn)p_klname("kernel_read");
	p_kernel_write      = (kernel_write_fn)p_klname("kernel_write");
	p_kern_path         = (kern_path_fn)p_klname("kern_path");
	p_path_put          = (path_put_fn)p_klname("path_put");
	p_prepare_creds     = (prepare_creds_fn)p_klname("prepare_creds");
	p_commit_creds      = (commit_creds_fn)p_klname("commit_creds");
	p_override_creds    = (override_creds_fn)p_klname("override_creds");
	p_revert_creds      = (revert_creds_fn)p_klname("revert_creds");
	p_groups_alloc      = (groups_alloc_fn)p_klname("groups_alloc");
	p_groups_free       = (groups_free_fn)p_klname("groups_free");
	p_set_groups        = (set_groups_fn)p_klname("set_groups");
	p_secctx_to_secid   = (secctx_to_secid_fn)p_klname("security_secctx_to_secid");
	p_secid_to_secctx   = (secid_to_secctx_fn)p_klname("security_secid_to_secctx");
	p_release_secctx    = (release_secctx_fn)p_klname("security_release_secctx");
	p_ksys_umount       = (ksys_umount_fn)p_klname("ksys_umount");
	p_ksys_mount        = (ksys_mount_fn)p_klname("ksys_mount");
	p_tp_reg            = (tp_reg_fn)p_klname("tracepoint_probe_register");
	p_tp_unreg          = (tp_unreg_fn)p_klname("tracepoint_probe_unregister");
	p_tp_sync           = (tp_sync_fn)p_klname("tracepoint_synchronize_unregister");
	p_queue_work_on     = (queue_work_on_fn)p_klname("queue_work_on");
	p_flush_work        = (flush_work_fn)p_klname("flush_work");

	p_tp_sys_enter      = (void *)p_klname("__tracepoint_sys_enter");
	p_tp_sys_exit       = (void *)p_klname("__tracepoint_sys_exit");
	p_system_wq         = (struct workqueue_struct **)p_klname("system_wq");
	p_init_task         = (struct task_struct *)p_klname("init_task");

	if (!p_copy_to_user || !p_copy_from_user || !p_strncpy_from_user ||
	    !p_tp_reg || !p_tp_unreg || !p_tp_sys_enter) {
		printk(KERN_ERR "ksu095: failed to resolve critical symbols\n");
		return -ENOENT;
	}

	setup_su_permissive();

	spin_lock_init(&profile_lock);
	k_memset(g_profiles, 0, sizeof(g_profiles));
	init_default_profiles();

	INIT_WORK(&ksu_save_work, do_save_allow_list);
	INIT_WORK(&ksu_load_work, do_load_allow_list);

	/* Grant root to shell (2000) by default so adb/shell works */
	{
		struct app_profile sh_prof;
		k_memset(&sh_prof, 0, sizeof(sh_prof));
		sh_prof.version = KSU_APP_PROFILE_VER;
		sh_prof.current_uid = 2000;
		sh_prof.allow_su = true;
		sh_prof.rp_config.use_default = true;
		k_strcpy(sh_prof.key, "com.android.shell");
		ksu_set_app_profile(&sh_prof, false);
	}

	/* Auto-detect Manager UID if already installed */
	detect_manager_uid_by_path("/data/data/me.weishu.kernelsu");

	/* Load persisted allowlist if /data is already mounted */
	do_load_allow_list(NULL);

	rc = p_tp_reg(p_tp_sys_enter, (void *)ksu_sys_enter_probe, NULL);
	if (rc) {
		printk(KERN_ERR "ksu095: register sys_enter failed: %d\n", rc);
		return rc;
	}
	tp_enter_registered = true;

	if (p_tp_sys_exit) {
		if (p_tp_reg(p_tp_sys_exit, (void *)ksu_sys_exit_probe, NULL) == 0)
			tp_exit_registered = true;
	}

	printk(KERN_INFO "ksu095: KernelSU v0.9.5 (%d) LKM loaded (mgr_uid=%d)\n",
	       KERNEL_SU_VERSION, (int)ksu_manager_uid);

	if (misc_register(&ksu095_misc))
		printk(KERN_ERR "ksu095: misc_register failed\n");
	return 0;
}

static void __exit ksu095_exit(void)
{
	misc_deregister(&ksu095_misc);

	if (tp_exit_registered && p_tp_unreg && p_tp_sys_exit)
		p_tp_unreg(p_tp_sys_exit, (void *)ksu_sys_exit_probe, NULL);

	if (tp_enter_registered && p_tp_unreg && p_tp_sys_enter)
		p_tp_unreg(p_tp_sys_enter, (void *)ksu_sys_enter_probe, NULL);

	if (p_tp_sync)
		p_tp_sync();

	if (p_flush_work) {
		p_flush_work(&ksu_save_work);
		p_flush_work(&ksu_load_work);
	}

	printk(KERN_INFO "ksu095: unloaded\n");
}

module_init(ksu095_init);
module_exit(ksu095_exit);

/* Provide LSE atomic helpers in case compiler emits them */
asm(
".arch_extension lse\n"
".globl __ll_sc_atomic_add\n"
".type __ll_sc_atomic_add, %function\n"
"__ll_sc_atomic_add:\n"
"  ldadd w1, w2, [x0]\n"
"  add   w0, w2, w1\n"
"  ret\n"
".size __ll_sc_atomic_add, .-__ll_sc_atomic_add\n"
".globl __ll_sc_atomic_sub_return\n"
".type __ll_sc_atomic_sub_return, %function\n"
"__ll_sc_atomic_sub_return:\n"
"  neg   w1, w1\n"
"  ldadd w1, w2, [x0]\n"
"  add   w0, w2, w1\n"
"  ret\n"
".size __ll_sc_atomic_sub_return, .-__ll_sc_atomic_sub_return\n"
);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelSU");
MODULE_DESCRIPTION("KernelSU v0.9.5 LKM Driver for 4.19");
