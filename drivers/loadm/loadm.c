/*
 * loadm - the only job is loading kernel modules from kernel context.
 *
 * It exposes /dev/loadm with one ioctl: pass a path, get the module loaded
 * through __arm64_sys_finit_module().  Running inside the kernel means the
 * caller's seccomp filter is irrelevant.
 *
 * The address of kallsyms_lookup_name cannot be discovered in-kernel on this
 * build (CONFIG_KPROBES is off), so it is handed over as a module parameter
 * when the module is inserted:
 *
 *   insmod loadm.ko klname_addr=0xffffff.....
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/string.h>

typedef unsigned long (*klname_fn)(const char *);
typedef long (*sysfn_fn)(const struct pt_regs *);

static unsigned long klname_addr;
module_param(klname_addr, ulong, 0444);
MODULE_PARM_DESC(klname_addr, "address of kallsyms_lookup_name");

static klname_fn p_klname;

/* The loader that inserts this module passes no parameters, so fall back to
 * the file userspace prepares with the resolved address. */
static unsigned long read_addr_file(void)
{
	struct file *f;
	char buf[32];
	ssize_t n;
	unsigned long v = 0;

	f = filp_open("/data/local/tmp/kl_addr", O_RDONLY, 0);
	if (IS_ERR(f))
		return 0;
	n = kernel_read(f, buf, sizeof(buf) - 1, &f->f_pos);
	filp_close(f, NULL);
	if (n > 0) {
		buf[n] = 0;
		v = simple_strtoul(buf, NULL, 0);
	}
	return v;
}

static int load_module_path(const char __user *upath)
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
	if (!sysfn) {
		pr_err("loadm: finit_module not found\n");
		return -ENOSYS;
	}

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
	/* uargs must be a user pointer: aim at the NUL that ends the path. */
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

	pr_info("loadm: %s -> %d\n", path, ret);
	return ret;
}

static long loadm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (cmd != 0x4b02)
		return -EINVAL;
	return load_module_path((const char __user *)arg);
}

static const struct file_operations loadm_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = loadm_ioctl,
	.compat_ioctl   = loadm_ioctl,
};

static struct miscdevice loadm_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "loadm",
	.fops  = &loadm_fops,
	.mode  = 0666,
};

static int __init loadm_init(void)
{
	int ret;

	if (!klname_addr)
		klname_addr = read_addr_file();

	if (klname_addr) {
		p_klname = (klname_fn)klname_addr;
		pr_info("loadm: klname=%px\n", p_klname);
	}

	ret = misc_register(&loadm_dev);
	if (ret) {
		pr_err("loadm: misc_register %d\n", ret);
		return ret;
	}
	pr_info("loadm: /dev/loadm ready\n");
	return 0;
}

static void __exit loadm_exit(void)
{
	misc_deregister(&loadm_dev);
}

module_init(loadm_init);
module_exit(loadm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernel-side module loader");
