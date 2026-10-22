// SPDX-License-Identifier: GPL-2.0
/* Bisect module: imports nothing but module_layout.
 *
 * If this loads, the loader path and the module_layout CRC we harvest from
 * kernel/module.o are both correct, and the failure of the real khack is one
 * of its other four imports. If it does not load, the vendor kernel's struct
 * layouts differ from this tree and no combination of CRCs will help.
 */
#include <linux/module.h>
#include <linux/kernel.h>

static int __init khack_init(void)
{
	pr_info("khack: minimal module loaded\n");
	return 0;
}

static void __exit khack_exit(void)
{
}

module_init(khack_init);
module_exit(khack_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("module_layout probe");
