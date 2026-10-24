#include <linux/module.h>
#include <linux/tty.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <asm/tlbflush.h>
#include <linux/version.h>
#include <linux/capability.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

#define THOOK_LOG_ENABLE 0   // 0为关闭，1为开启

#define THOOK_LOG(fmt, ...) \
    do { if (THOOK_LOG_ENABLE) printk(KERN_INFO "[Thook] " fmt, ##__VA_ARGS__); } while (0)


#define bits(n, high, low) (((n) << (63u - (high))) >> (63u - (high) + (low)))

typedef asmlinkage long (*syscall_ioctl_t)(unsigned int fd, unsigned int cmd, unsigned long arg);
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef long (*new_syscall_ioctl_t)(const struct pt_regs *);
kallsyms_lookup_name_t (*my_kallsyms_lookup_name)(const char *name);
unsigned long *__sys_call_table;
unsigned long start_address;
unsigned long finish_address;
syscall_ioctl_t original_ioctl;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 14, 186)
    new_syscall_ioctl_t new_original_ioctl;
#endif

static int setts(int value) {
    struct file *file;
    loff_t pos = 0;
    char buf[2];

    file = filp_open("/proc/sys/kernel/kptr_restrict", O_WRONLY, 0);
    if (IS_ERR(file)) {
        THOOK_LOG("Failed to open /proc/sys/kernel/kptr_restrict\n");
        return -EFAULT;
    }
    snprintf(buf, sizeof(buf), "%d", value);
    ssize_t written = kernel_write(file, buf, strlen(buf), &pos);
    filp_close(file, NULL);

    THOOK_LOG("Set /proc/sys/kernel/kptr_restrict to %d, ret=%zd\n", value, written);
    return (written > 0) ? 0 : -EFAULT;
}



static uintptr_t read_kallsyms(const char *symbol) {
    struct file *file;
    loff_t pos = 0;
    char *buf;
    char sym_name[256];
    char *addr_str;
    char *type_str;
    char *name_str;
    uintptr_t addr;
    char type;
    mm_segment_t old_fs;
    struct seq_file *seq;
    int found = 0;

    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        THOOK_LOG("Failed to open kallsyms\n");
        return -EFAULT;
    }

    old_fs = get_fs();
    set_fs(get_ds());

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf) {
        filp_close(file, NULL);
        set_fs(old_fs);
        THOOK_LOG("Failed to allocate buffer in read_kallsyms\n");
        return -ENOMEM;
    }

    seq = file->private_data;
    if (!seq) {
        THOOK_LOG("Failed to get seq_file from kallsyms\n");
        kfree(buf);
        filp_close(file, NULL);
        set_fs(old_fs);
        return -EFAULT;
    }

    while (seq_read(file, buf, 4096, &pos) > 0) {
        char *line = buf;
        while (*line) {
            char *end = strchr(line, '\n');
            if (end) *end = '\0';
            addr_str = line;
            type_str = strchr(line, ' ');
            if (!type_str) break;
            *type_str++ = '\0';
            name_str = strchr(type_str, ' ');
            if (!name_str) break;
            *name_str++ = '\0';

            addr = simple_strtoull(addr_str, NULL, 16);
            type = *type_str;
            strncpy(sym_name, name_str, sizeof(sym_name) - 1);
            sym_name[sizeof(sym_name) - 1] = '\0';

            if (strcmp(sym_name, symbol) == 0) {
                THOOK_LOG("Found symbol %s at %llx type %c\n", sym_name, addr, type);
                found = 1;
                kfree(buf);
                filp_close(file, NULL);
                set_fs(old_fs);
                return addr;
            }

            if (end) line = end + 1;
            else break;
        }
    }
    kfree(buf);
    filp_close(file, NULL);
    set_fs(old_fs);
    if (!found) THOOK_LOG("Symbol %s not found in kallsyms\n", symbol);
    return -1;
}

unsigned long get_kallsyms_lookup_name_addr(void)
{
    unsigned long ret = 0;
    setts(0);
    ret = read_kallsyms("kallsyms_lookup_name");
    THOOK_LOG("kallsyms_lookup_name addr: %lx\n", ret);
    return ret;
}

static uint64_t page_size_t = 0;
static uint64_t page_level_c = 0;
static uint64_t page_shift_t = 0;
static uint64_t pgd_k_pa = 0;
static uint64_t pgd_k = 0;

__attribute__((no_sanitize("cfi"))) void init_page_util(void)
{
    uint64_t tcr_el1;
    uint64_t ttbr1_el1;
    uint64_t va_bits;
    uint64_t t1sz, tg1, baddr, page_size_mask;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

    t1sz = bits(tcr_el1, 21, 16);
    tg1 = bits(tcr_el1, 31, 30);
    va_bits = 64 - t1sz;
    page_shift_t = 12;
    if (tg1 == 1) page_shift_t = 14;
    else if (tg1 == 3) page_shift_t = 16;
    page_size_t = 1 << page_shift_t;
    page_level_c = (va_bits - 4) / (page_shift_t - 3);

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1_el1));
    baddr = ttbr1_el1 & 0xFFFFFFFFFFFE;
    page_size_mask = ~(page_size_t - 1);
    pgd_k_pa = baddr & page_size_mask;
    pgd_k = (uint64_t)phys_to_virt(pgd_k_pa);

    THOOK_LOG("page_size_t: %lx, page_level_c: %lx, page_shift_t: %lx\n", page_size_t, page_level_c, page_shift_t);
    THOOK_LOG("pgd_k_pa: %lx, pgd_k: %lx\n", pgd_k_pa, pgd_k);
}

uint64_t *pgtable_entry(uint64_t pgd, uint64_t va)
{
    uint64_t pxd_bits = page_shift_t - 3;
    uint64_t pxd_ptrs = 1u << pxd_bits;
    uint64_t pxd_va = pgd;
    uint64_t pxd_pa = virt_to_phys((void*)pxd_va);
    uint64_t pxd_entry_va = 0;
    uint64_t block_lv = 0;
    int64_t lv = 0;
    if(page_shift_t == 0 || page_level_c == 0 || page_shift_t == 0)
        return NULL;
    for (lv = 4 - page_level_c; lv < 4; lv++) {
        uint64_t pxd_shift = (page_shift_t - 3) * (4 - lv) + 3;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);
        pxd_entry_va = pxd_va + pxd_index * 8;
        if (!pxd_entry_va) return 0;
        uint64_t pxd_desc = *((uint64_t *)pxd_entry_va);
        if ((pxd_desc & 0b11) == 0b11) {
            pxd_pa = pxd_desc & (((1ul << (48 - page_shift_t)) - 1) << page_shift_t);
        } else if ((pxd_desc & 0b11) == 0b01) {
            uint64_t block_bits = (3 - lv) * pxd_bits + page_shift_t;
            pxd_pa = pxd_desc & (((1ul << (48 - block_bits)) - 1) << block_bits);
            block_lv = lv;
        } else {
            return 0;
        }
        pxd_va = (uint64_t)phys_to_virt((phys_addr_t)pxd_pa);
        if (block_lv) {
            break;
        }
    }
    return (uint64_t *)pxd_entry_va;
}

inline uint64_t *pgtable_entry_kernel(uint64_t va)
{
    return pgtable_entry(pgd_k, va);
}

static inline int thook_permission_check(void)
{
    // 只允许 root（CAP_SYS_ADMIN）
    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }
    return 0;
}
long handle_ioctl(unsigned int fd, unsigned int const cmd, unsigned long const arg)
{
    int perm_ret;
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    perm_ret = thook_permission_check();
    if (perm_ret) {
        THOOK_LOG("Permission denied: uid=%d cmd=0x%x\n",
              __kuid_val(current_uid()), cmd);
    return perm_ret;
}

    THOOK_LOG("handle_ioctl: fd=%u, cmd=0x%x, arg=0x%lx\n", fd, cmd, arg);

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                THOOK_LOG("copy_from_user OP_READ_MEM failed\n");
                return -1;
            }
            if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                THOOK_LOG("read_process_memory failed\n");
                return -1;
            }
            break;
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                THOOK_LOG("copy_from_user OP_WRITE_MEM failed\n");
                return -1;
            }
            if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                THOOK_LOG("write_process_memory failed\n");
                return -1;
            }
            break;
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 
                || copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
                THOOK_LOG("copy_from_user OP_MODULE_BASE failed\n");
                return -1;
            }
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                THOOK_LOG("copy_to_user OP_MODULE_BASE failed\n");
                return -1;
            }
            break;
        default:
            THOOK_LOG("Unknown ioctl cmd: 0x%x\n", cmd);
            break;
    }
    return 0;
}

long new_hook_ioctl(const struct pt_regs *kregs)
{
    long ret = 0;
    unsigned int fd = (unsigned int)kregs->regs[0];
    unsigned int cmd = (unsigned int)kregs->regs[1];
    unsigned long arg = (unsigned long)kregs->regs[2];

    if (fd==-1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE)
        ret = handle_ioctl(fd, cmd, arg);
    else {
        // 🔥🔥 这里必须加，避免 new_original_ioctl 为 NULL 导致崩溃
        if (!new_original_ioctl) {
            THOOK_LOG("new_original_ioctl is NULL! block syscall\n");
            return -ENOSYS;
        }
        ret = new_original_ioctl(kregs);
    }

    return ret;
}


asmlinkage long hook_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    long ret = 0;
    

    if (fd==-1 && cmd >= OP_INIT_KEY && cmd <= OP_MODULE_BASE)
        ret = handle_ioctl(fd, cmd, arg);
    else
        ret = original_ioctl(fd, cmd, arg);

    return ret;
}

static int hook_func(unsigned long hook_function, int nr,
        unsigned long *sys_table)
{
    uint64_t orginal_pte;
    uint64_t *pte;
    THOOK_LOG("hook_func: hook_function=0x%lx, nr=%d, sys_table=%px\n", hook_function, nr, sys_table);

    if(nr<0) {
        THOOK_LOG("hook_func: invalid nr=%d\n", nr);
        return 3004;
    }

    pte = pgtable_entry_kernel((uint64_t)&sys_table[nr]);
    if(pte == NULL) {
        THOOK_LOG("hook_func: failed to get pte\n");
        return 3007;
    }

    orginal_pte = *pte;
    *pte = (orginal_pte | PTE_DBM) & ~PTE_RDONLY;
    flush_tlb_all();

    sys_table[nr] = hook_function;

    *pte = orginal_pte;
    flush_tlb_all();

    THOOK_LOG("hook_func finished\n");
    return 0;
}

static int __init my_module_init(void) {

    THOOK_LOG("init_page_util...\n");
    init_page_util();

    // 获取 sys_call_table
    THOOK_LOG("read_kallsyms(sys_call_table)...\n");
    __sys_call_table = (unsigned long *)read_kallsyms("sys_call_table");
    if (!__sys_call_table) {
        THOOK_LOG("Cannot find sys_call_table!\n");
        return -1;
    }

    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 186)
        THOOK_LOG("hook_func hook_ioctl (__NR_ioctl)...\n");
        hook_func((unsigned long)hook_ioctl, __NR_ioctl, __sys_call_table);
    #else
        // 🔥🔥 必须加上这两行！（保存原始指针，避免炸机）
        new_original_ioctl = (new_syscall_ioctl_t)__sys_call_table[__NR_ioctl];
        THOOK_LOG("saved new_original_ioctl = %px\n", new_original_ioctl);
        THOOK_LOG("hook_func new_hook_ioctl (__NR_ioctl)...\n");
        hook_func((unsigned long)new_hook_ioctl, __NR_ioctl, __sys_call_table);
    #endif
    
    if (!IS_ERR(filp_open("/proc/sched_debug", O_RDONLY, 0))) {
        THOOK_LOG("removing /proc/sched_debug\n");
        remove_proc_subtree("sched_debug", NULL);
    }
    if (!IS_ERR(filp_open("/proc/uevents_records", O_RDONLY, 0))) {
        THOOK_LOG("removing /proc/uevents_records\n");
        remove_proc_entry("uevents_records", NULL);
    }

    
       list_del(&THIS_MODULE->list);
       kobject_del(&THIS_MODULE->mkobj.kobj);
       list_del(&THIS_MODULE->mkobj.kobj.entry);

    THOOK_LOG("init finish!\n");
    return 0;
}

static void __exit my_module_exit(void) {
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 191)
        THOOK_LOG("restore original_ioctl (__NR_ioctl)...\n");
        hook_func((unsigned long)original_ioctl, __NR_ioctl, __sys_call_table);
    #else
        THOOK_LOG("restore new_original_ioctl (__NR_ioctl)...\n");
        hook_func((unsigned long)new_original_ioctl, __NR_ioctl, __sys_call_table);
    #endif
    THOOK_LOG("exit finish!\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom syscall module without kprobes");
MODULE_AUTHOR("万载");

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
    MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver); 
#endif
