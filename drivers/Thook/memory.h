#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if(pgd_none(*pgd) || pgd_bad(*pgd)) {
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		return 0;
	}
	pud = pud_offset(p4d,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
		return 0;
	}
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
		return 0;
	}
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
		return 0;
	}
	if(!pte_present(*pte)) {
		return 0;
	}
	//页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE-1);

	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if(pgd_none(*pgd) || pgd_bad(*pgd)) {
		return 0;
	}
	pud = pud_offset(pgd,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
		return 0;
	}
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
		return 0;
	}
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
		return 0;
	}
	if(!pte_present(*pte)) {
		return 0;
	}
	//页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE-1);

	return page_addr + page_offset;
}
#endif

#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static size_t get_high_memory(void)
{
	struct sysinfo meminfo;
	si_meminfo(&meminfo);
	return (meminfo.totalram * (meminfo.mem_unit / 1024)) << PAGE_SHIFT;
}
#define valid_phys_addr_range(addr, count) (addr + count <= get_high_memory())
#else
#define valid_phys_addr_range(addr, count) true
#endif

size_t read_physical_address(phys_addr_t pa, void* buffer, size_t size) {
	void* mapped;

	if (!pfn_valid(__phys_to_pfn(pa))) {
		return 0;
	}
	if (!valid_phys_addr_range(pa, size)) {
		return 0;
	}
	mapped = ioremap_cache(pa, size);
	if (!mapped) {
		return 0;
	}
	if(copy_to_user(buffer, mapped, size)) {
		iounmap(mapped);
		return 0;
	}
	iounmap(mapped);
	return size;
}

size_t write_physical_address(phys_addr_t pa, void* buffer, size_t size) {
	void* mapped;

	if (!pfn_valid(__phys_to_pfn(pa))) {
		return 0;
	}
	if (!valid_phys_addr_range(pa, size)) {
		return 0;
	}
	mapped = ioremap_cache(pa, size);
	if (!mapped) {
		return 0;
	}
	if(copy_from_user(mapped, buffer, size)) {
		iounmap(mapped);
		return 0;
	}
	iounmap(mapped);
	return size;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
	struct task_struct *task;
	int copied;

	if (!buffer || !size || addr + size < addr)
		return false;

	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task)
		return false;

	/* access_process_vm walks the target's page tables, faults pages in when
	 * needed and refuses to touch anything that is not mapped, so a bad
	 * address returns a short count instead of corrupting the kernel. */
	copied = access_process_vm(task, addr, buffer, size, FOLL_FORCE);
	return copied == (int)size;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
	struct task_struct *task;
	int copied;

	if (!buffer || !size || addr + size < addr)
		return false;

	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task)
		return false;

	copied = access_process_vm(task, addr, buffer, size, FOLL_FORCE | FOLL_WRITE);
	return copied == (int)size;
}
