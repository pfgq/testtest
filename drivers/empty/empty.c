/* Empty test module: proves the loader path works without side effects. */
#include <linux/module.h>
#include <linux/kernel.h>

static int __init empty_init(void)
{
	pr_info("empty: loaded\n");
	return 0;
}

static void __exit empty_exit(void)
{
}

module_init(empty_init);
module_exit(empty_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("empty test module");
