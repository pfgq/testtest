/*
 * atomic_shim - export the LL/SC atomic helper that LSE-built kernels omit.
 *
 * Third-party modules compiled against a non-LSE kernel reference
 * __ll_sc_atomic64_*; those symbols do not exist here, so the module refuses
 * to load with "Unknown symbol".  This shim provides the missing entry points
 * on top of the generic atomic API and exports them.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/atomic.h>

void __ll_sc_atomic64_or(atomic64_t *v, long a)
{
	atomic64_or(a, v);
}
EXPORT_SYMBOL(__ll_sc_atomic64_or);

void __ll_sc_atomic64_and(atomic64_t *v, long a)
{
	atomic64_and(a, v);
}
EXPORT_SYMBOL(__ll_sc_atomic64_and);

void __ll_sc_atomic64_andnot(atomic64_t *v, long a)
{
	atomic64_andnot(a, v);
}
EXPORT_SYMBOL(__ll_sc_atomic64_andnot);

void __ll_sc_atomic64_add(long i, atomic64_t *v)
{
	atomic64_add(i, v);
}
EXPORT_SYMBOL(__ll_sc_atomic64_add);

void __ll_sc_atomic64_sub(long i, atomic64_t *v)
{
	atomic64_sub(i, v);
}
EXPORT_SYMBOL(__ll_sc_atomic64_sub);

static int __init atomic_shim_init(void)
{
	pr_info("atomic_shim: ll/sc helpers exported\n");
	return 0;
}

static void __exit atomic_shim_exit(void)
{
}

module_init(atomic_shim_init);
module_exit(atomic_shim_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LL/SC atomic helper shim");
