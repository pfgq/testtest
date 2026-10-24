#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/ptrace.h>

/* ================= ioctl ================= */

#define HWHOOK_IOCTL_MAGIC  0xF7
#define HWHOOK_IOCTL_START  _IOWR(HWHOOK_IOCTL_MAGIC, 1, struct hwhook_request)

#define HWHOOK_MODE_READ 1
#define HWHOOK_MODE_HOOK 2

/* reg_index:
 * 0~30 : x0~x30
 * 31   : sp
 * 32   : pc
 */

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

/* ================= 全局状态 ================= */

static struct perf_event *g_bp;
static struct task_struct *g_task;
static struct perf_event_attr g_orig_attr;
static struct perf_event_attr g_next_attr;

static struct hwhook_request g_req;

static bool g_second_hit;
static bool g_hit_done;

static DEFINE_MUTEX(g_lock);
static wait_queue_head_t g_waitq;

/* ★ 来自 hw_breakpoint.c 的全局 gate mutex */
DEFINE_MUTEX(hwhook_gate_lock);   /* upstream left this undefined */

/* ================= HWBP 回调 ================= */

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

    printk(KERN_INFO
           "[hwhook] HIT pc=0x%llx x0=0x%llx\n",
           regs->pc, regs->regs[0]);

    if (!g_second_hit && g_req.mode == HWHOOK_MODE_HOOK) {
        if (g_req.reg_index < 31)
            regs->regs[g_req.reg_index] = g_req.new_value;
        else if (g_req.reg_index == 31)
            regs->sp = g_req.new_value;
        else if (g_req.reg_index == 32)
            regs->pc = g_req.new_value;

        printk(KERN_INFO
               "[hwhook] hook reg %u -> 0x%llx\n",
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

/* ================= ioctl ================= */

static long hwhook_ioctl(struct file *file,
                         unsigned int cmd,
                         unsigned long arg)
{
    struct pid *pid_struct;

    if (cmd != HWHOOK_IOCTL_START)
        return -EINVAL;

    if (copy_from_user(&g_req, (void __user *)arg, sizeof(g_req)))
        return -EFAULT;

    mutex_lock(&g_lock);

    g_hit_done   = false;
    g_second_hit = false;

    if (g_bp) {
        unregister_hw_breakpoint(g_bp);
        g_bp = NULL;
    }

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
    g_orig_attr.bp_addr = g_req.bp_addr;
    g_orig_attr.bp_len  = HW_BREAKPOINT_LEN_4;
    g_orig_attr.bp_type = HW_BREAKPOINT_X;
    g_orig_attr.disabled = 0;

    /* ★★★ 核心：持有 gate mutex 的上下文里注册 BRP ★★★ */
    mutex_lock(&hwhook_gate_lock);

    g_bp = register_user_hw_breakpoint(
        &g_orig_attr, hwhook_handler, NULL, g_task);

    mutex_unlock(&hwhook_gate_lock);
    /* ★★★ gate 结束 ★★★ */

    if (IS_ERR(g_bp)) {
        g_bp = NULL;
        mutex_unlock(&g_lock);
        return -EPERM;
    }

    printk(KERN_INFO
           "[hwhook] HWBP installed pid=%d addr=0x%llx\n",
           g_req.pid, g_req.bp_addr);

    mutex_unlock(&g_lock);

    wait_event_interruptible(g_waitq, g_hit_done);

    mutex_lock(&g_lock);

    if (copy_to_user((void __user *)arg, &g_req, sizeof(g_req))) {
        mutex_unlock(&g_lock);
        return -EFAULT;
    }

    mutex_unlock(&g_lock);
    return 0;
}

/* ================= 设备 ================= */

static const struct file_operations hwhook_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = hwhook_ioctl,
};

static struct miscdevice hwhook_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "hwhook",
    .fops  = &hwhook_fops,
};

static int __init hwhook_init(void)
{
    init_waitqueue_head(&g_waitq);
    misc_register(&hwhook_dev);
    printk(KERN_INFO "[hwhook] module loaded\n");
    return 0;
}

static void __exit hwhook_exit(void)
{
    if (g_bp)
        unregister_hw_breakpoint(g_bp);
    misc_deregister(&hwhook_dev);
    printk(KERN_INFO "[hwhook] module unloaded\n");
}

module_init(hwhook_init);
module_exit(hwhook_exit);
MODULE_LICENSE("GPL");
