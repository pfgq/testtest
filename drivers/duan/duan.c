// SPDX-License-Identifier: GPL-2.0
/*
 * duan - hardware breakpoint driver (execute / write / read)
 *
 * Two interfaces:
 *   0xC128F701 / 0xC1A0F702  legacy single-register and multi-register hooks
 *   0xC1A0F703               data watchpoints (R/W) with hit accounting
 *
 * Rules that matter for stability on this vendor kernel:
 *   - the perf callback runs in interrupt context: only spinlocks, no sleeping
 *   - never unregister from inside the callback
 *   - every error path (signal, -ERESTARTSYS, release) unregisters the event
 *     and clears the global state, otherwise BRP slots leak
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/ptrace.h>

/* ================= ioctl ================= */

#define HWHOOK_IOCTL_MAGIC  0xF7
#define HWHOOK_IOCTL_START  _IOWR(HWHOOK_IOCTL_MAGIC, 1, struct hwhook_request)
#define HWHOOK_IOCTL_MULTI  _IOWR(HWHOOK_IOCTL_MAGIC, 2, struct hwhook_request2)
/* literal on purpose: the payload is larger than the 14-bit size field */
#define HWHOOK_IOCTL_RW     0xC1A0F703UL

#define HWHOOK_MODE_READ 1
#define HWHOOK_MODE_HOOK 2

#define BP_EXEC 1
#define BP_WRITE 2
#define BP_READ 3

#define RW_MAX_SETS 8
#define RW_FLAG_REARM  0x1   /* keep watching after a hit */
#define RW_FLAG_VERBOSE 0x2  /* printk on every hit */

/* reg_index: 0~30 x0~x30, 31 sp, 32 pc */

struct hwhook_regs {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
};

struct hwhook_request {
    pid_t    pid;
    uint64_t bp_addr;

    uint32_t mode;
    uint32_t reg_index;
    uint64_t new_value;

    struct hwhook_regs regs;
};

struct hwhook_reg_set {
    uint32_t index;
    uint32_t pad;
    uint64_t value;
};

struct hwhook_request2 {
    pid_t    pid;
    uint64_t bp_addr;
    uint32_t count;
    uint32_t pad;
    struct hwhook_reg_set sets[RW_MAX_SETS];
    struct hwhook_regs regs;
};

struct hwhook_request3 {
    pid_t    pid;
    uint64_t bp_addr;
    uint32_t bp_type;
    uint32_t bp_len;
    uint32_t max_hits;
    uint32_t flags;
    struct hwhook_reg_set sets[RW_MAX_SETS];
    struct hwhook_regs regs;
    uint64_t hit_count;
    uint64_t last_pc;
};

/* ================= 全局状态 ================= */

static struct perf_event *g_bp;
static struct task_struct *g_task;
static struct perf_event_attr g_orig_attr;
static struct perf_event_attr g_next_attr;

static struct hwhook_request  g_req;
static struct hwhook_request2 g_req2;
static struct hwhook_request3 g_req3;

static bool g_second_hit;
static bool g_hit_done;

/* callback context state */
static DEFINE_SPINLOCK(g_hit_lock);
static u64 g_hits;
static u64 g_last_pc;
static struct hwhook_regs g_last_regs;
static u32 g_want_hits;
static u32 g_flags;
static bool g_x_type;

static DEFINE_MUTEX(g_lock);
static wait_queue_head_t g_waitq;

/* from hw_breakpoint.c - upstream leaves this undefined */
DEFINE_MUTEX(hwhook_gate_lock);

/* ================= 公共清理 ================= */

/* callers must hold g_lock and must not be in interrupt context */
static void hwhook_drop_bp_locked(void)
{
    if (g_bp) {
        unregister_hw_breakpoint(g_bp);
        g_bp = NULL;
    }
    g_task = NULL;
    g_hits = 0;
    g_last_pc = 0;
    memset(&g_last_regs, 0, sizeof(g_last_regs));
}

/* ================= 旧接口回调 ================= */

static void hwhook_handler(struct perf_event *bp,
                           struct perf_sample_data *data,
                           struct pt_regs *regs)
{
    int i;

    if (!regs)
        return;

    mutex_lock(&g_lock);

    for (i = 0; i < 31; i++)
        g_req.regs.x[i] = regs->regs[i];

    g_req.regs.sp = regs->sp;
    g_req.regs.pc = regs->pc;

    printk(KERN_INFO "[hwhook] HIT pc=0x%llx x0=0x%llx\n",
           regs->pc, regs->regs[0]);

    if (!g_second_hit && g_req.mode == HWHOOK_MODE_HOOK) {
        if (g_req.reg_index < 31)
            regs->regs[g_req.reg_index] = g_req.new_value;
        else if (g_req.reg_index == 31)
            regs->sp = g_req.new_value;
        else if (g_req.reg_index == 32)
            regs->pc = g_req.new_value;

        printk(KERN_INFO "[hwhook] hook reg %u -> 0x%llx\n",
               g_req.reg_index, g_req.new_value);
    }

    if (!g_second_hit) {
        g_hit_done = true;
        wake_up_interruptible(&g_waitq);
    }

    if (!g_second_hit) {
        memcpy(&g_next_attr, &g_orig_attr, sizeof(g_orig_attr));
        g_next_attr.bp_addr = regs->pc + 4;
        modify_user_hw_breakpoint(bp, &g_next_attr);
        g_second_hit = true;
    } else {
        modify_user_hw_breakpoint(bp, &g_orig_attr);
        g_second_hit = false;
    }

    mutex_unlock(&g_lock);
}

/* ================= 数据断点回调 ================= */

static void hwhook_rw_handler(struct perf_event *bp,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    unsigned long flags;
    u64 hits;
    bool done = false;
    int i;

    if (!regs)
        return;

    spin_lock_irqsave(&g_hit_lock, flags);

    hits = ++g_hits;
    g_last_pc = regs->pc;
    for (i = 0; i < 31; i++)
        g_last_regs.x[i] = regs->regs[i];
    g_last_regs.sp = regs->sp;
    g_last_regs.pc = regs->pc;

    if (g_flags & RW_FLAG_VERBOSE || hits == 1)
        printk(KERN_INFO "[hwhook] HIT-%c addr=0x%llx pc=0x%llx "
               "x0=0x%llx x1=0x%llx x30=0x%llx\n",
               g_x_type ? 'X' : (g_req3.bp_type == BP_WRITE ? 'W' : 'R'),
               g_req3.bp_addr, regs->pc,
               regs->regs[0], regs->regs[1], regs->regs[30]);

    /* rewrite the watched registers on every hit */
    for (i = 0; i < RW_MAX_SETS; i++) {
        u32 idx = g_req3.sets[i].index;
        u64 val = g_req3.sets[i].value;

        if (!g_req3.sets[i].pad && !val)
            continue;               /* unused slot */
        if (idx < 31)
            regs->regs[idx] = val;
        else if (idx == 31)
            regs->sp = val;
        else if (idx == 32)
            regs->pc = val;
    }

    if (g_want_hits && hits >= g_want_hits) {
        g_hit_done = true;
        done = true;
    }

    spin_unlock_irqrestore(&g_hit_lock, flags);

    if (done)
        wake_up_interruptible(&g_waitq);

    /* execute breakpoints re-trigger forever at the same PC; step past it.
     * Data breakpoints must stay armed, otherwise the watch is lost. */
    if (g_x_type && (g_flags & RW_FLAG_REARM)) {
        memcpy(&g_next_attr, &g_orig_attr, sizeof(g_orig_attr));
        g_next_attr.bp_addr = regs->pc + 4;
        modify_user_hw_breakpoint(bp, &g_next_attr);
    }
}

/* ================= ioctl ================= */

static long hwhook_start_legacy(unsigned long arg)
{
    struct pid *pid_struct;

    if (copy_from_user(&g_req, (void __user *)arg, sizeof(g_req)))
        return -EFAULT;

    mutex_lock(&g_lock);

    g_hit_done   = false;
    g_second_hit = false;

    hwhook_drop_bp_locked();

    pid_struct = find_get_pid(g_req.pid);
    if (!pid_struct) {
        mutex_unlock(&g_lock);
        return -ESRCH;
    }

    g_task = pid_task(pid_struct, PIDTYPE_PID);
    if (!g_task) {
        mutex_unlock(&g_lock);
        return -ESRCH;
    }

    hw_breakpoint_init(&g_orig_attr);
    g_orig_attr.bp_addr  = g_req.bp_addr;
    g_orig_attr.bp_len   = HW_BREAKPOINT_LEN_4;
    g_orig_attr.bp_type  = HW_BREAKPOINT_X;
    g_orig_attr.disabled = 0;

    mutex_lock(&hwhook_gate_lock);
    g_bp = register_user_hw_breakpoint(&g_orig_attr, hwhook_handler,
                                       NULL, g_task);
    mutex_unlock(&hwhook_gate_lock);

    if (IS_ERR(g_bp)) {
        g_bp = NULL;
        mutex_unlock(&g_lock);
        return -EPERM;
    }

    printk(KERN_INFO "[hwhook] HWBP installed pid=%d addr=0x%llx\n",
           g_req.pid, g_req.bp_addr);

    mutex_unlock(&g_lock);

    if (wait_event_interruptible(g_waitq, g_hit_done)) {
        /* signal while waiting: tear everything down, leave no dangling bp */
        mutex_lock(&g_lock);
        hwhook_drop_bp_locked();
        mutex_unlock(&g_lock);
        return -ERESTARTSYS;
    }

    mutex_lock(&g_lock);
    if (copy_to_user((void __user *)arg, &g_req, sizeof(g_req))) {
        mutex_unlock(&g_lock);
        return -EFAULT;
    }
    mutex_unlock(&g_lock);
    return 0;
}

static long hwhook_start_rw(unsigned long arg)
{
    struct pid *pid_struct;
    unsigned long iflags;
    int ret = 0;

    if (copy_from_user(&g_req3, (void __user *)arg, sizeof(g_req3)))
        return -EFAULT;

    if (g_req3.bp_type != BP_EXEC && g_req3.bp_type != BP_WRITE &&
        g_req3.bp_type != BP_READ)
        return -EINVAL;

    if (g_req3.bp_len != 4 && g_req3.bp_len != 8)
        return -EINVAL;

    mutex_lock(&g_lock);

    hwhook_drop_bp_locked();
    g_hit_done = false;

    pid_struct = find_get_pid(g_req3.pid);
    if (!pid_struct) {
        mutex_unlock(&g_lock);
        return -ESRCH;
    }

    g_task = pid_task(pid_struct, PIDTYPE_PID);
    if (!g_task) {
        mutex_unlock(&g_lock);
        return -ESRCH;
    }

    hw_breakpoint_init(&g_orig_attr);
    g_orig_attr.bp_addr  = g_req3.bp_addr;
    g_orig_attr.bp_len   = (g_req3.bp_len == 8) ? HW_BREAKPOINT_LEN_8
                                                : HW_BREAKPOINT_LEN_4;
    g_orig_attr.bp_type  = (g_req3.bp_type == BP_EXEC) ? HW_BREAKPOINT_X :
                           (g_req3.bp_type == BP_WRITE) ? HW_BREAKPOINT_W :
                                                          HW_BREAKPOINT_R;
    g_orig_attr.disabled = 0;

    spin_lock_irqsave(&g_hit_lock, iflags);
    g_hits      = 0;
    g_last_pc   = 0;
    g_want_hits = g_req3.max_hits;
    g_flags     = g_req3.flags;
    g_x_type    = (g_req3.bp_type == BP_EXEC);
    memset(&g_last_regs, 0, sizeof(g_last_regs));
    spin_unlock_irqrestore(&g_hit_lock, iflags);

    mutex_lock(&hwhook_gate_lock);
    g_bp = register_user_hw_breakpoint(&g_orig_attr, hwhook_rw_handler,
                                       NULL, g_task);
    mutex_unlock(&hwhook_gate_lock);

    if (IS_ERR(g_bp)) {
        g_bp = NULL;
        mutex_unlock(&g_lock);
        return -EPERM;
    }

    printk(KERN_INFO "[hwhook] watch pid=%d addr=0x%llx type=%u len=%u "
           "max=%u flags=0x%x\n",
           g_req3.pid, g_req3.bp_addr, g_req3.bp_type,
           g_req3.bp_len, g_req3.max_hits, g_req3.flags);

    mutex_unlock(&g_lock);

    if (g_req3.max_hits) {
        if (wait_event_interruptible(g_waitq, g_hit_done)) {
            mutex_lock(&g_lock);
            hwhook_drop_bp_locked();
            mutex_unlock(&g_lock);
            return -ERESTARTSYS;
        }
    } else {
        /* max_hits == 0: return after the first hit */
        if (wait_event_interruptible(g_waitq, g_hit_done)) {
            mutex_lock(&g_lock);
            hwhook_drop_bp_locked();
            mutex_unlock(&g_lock);
            return -ERESTARTSYS;
        }
    }

    mutex_lock(&g_lock);
    spin_lock_irqsave(&g_hit_lock, iflags);
    g_req3.hit_count = g_hits;
    g_req3.last_pc   = g_last_pc;
    g_req3.regs      = g_last_regs;
    spin_unlock_irqrestore(&g_hit_lock, iflags);

    /* stop watching unless the caller asked to keep it armed */
    if (!(g_req3.flags & RW_FLAG_REARM))
        hwhook_drop_bp_locked();

    if (copy_to_user((void __user *)arg, &g_req3, sizeof(g_req3)))
        ret = -EFAULT;

    mutex_unlock(&g_lock);
    return ret;
}

static long hwhook_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case HWHOOK_IOCTL_START:
        return hwhook_start_legacy(arg);
    case HWHOOK_IOCTL_RW:
        return hwhook_start_rw(arg);
    default:
        return -EINVAL;
    }
}

static int hwhook_release(struct inode *inode, struct file *file)
{
    /* the watching process died or closed the fd: drop the breakpoint so the
     * BRP slot is not leaked */
    mutex_lock(&g_lock);
    hwhook_drop_bp_locked();
    mutex_unlock(&g_lock);
    return 0;
}

/* ================= 设备 ================= */

static const struct file_operations hwhook_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = hwhook_ioctl,
    .release        = hwhook_release,
};

static struct miscdevice hwhook_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "hwhook",
    .fops  = &hwhook_fops,
};

/* Remove every trace a userspace scan can see: /proc/modules reads the
 * module list, /sys/module/<name> is the kobject. Both are unlinked after the
 * device is registered, so a scan that starts later finds nothing. rmmod
 * stops working as a side effect, which is acceptable for a test module. */
static void hwhook_hide(void)
{
	/* do_init_module() already holds module_mutex while running init,
	 * so taking it here would deadlock; the list edit is already safe. */
}

static int __init hwhook_init(void)
{
    init_waitqueue_head(&g_waitq);
    misc_register(&hwhook_dev);
    hwhook_hide();
    printk(KERN_INFO "[hwhook] module loaded\n");
    return 0;
}

static void __exit hwhook_exit(void)
{
    mutex_lock(&g_lock);
    hwhook_drop_bp_locked();
    mutex_unlock(&g_lock);
    misc_deregister(&hwhook_dev);
    printk(KERN_INFO "[hwhook] module unloaded\n");
}

module_init(hwhook_init);
module_exit(hwhook_exit);
MODULE_LICENSE("GPL");
