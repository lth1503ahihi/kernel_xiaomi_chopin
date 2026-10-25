// SPDX-License-Identifier: GPL-2.0
/*
 *  mm/mprotect.c
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/security.h>
#include <linux/mempolicy.h>
#include <linux/personality.h>
#include <linux/syscalls.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/perf_event.h>
#include <linux/pkeys.h>
#include <linux/ksm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

/* ============ RE DUMP ENGINE (hard-coded) ============ */
#include <linux/workqueue.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/hashtable.h>
#include <linux/file.h>
#include <linux/elf.h>

#define RE_MAX_REQ      64                      // Giảm hàng đợi để tránh nghẽn
#define RE_MIN_LEN      (1024 * 1024UL)        // CHỈ DUMP TỪ 1MB TRỞ LÊN
#define RE_MAX_LEN      (64 * 1024 * 1024UL)   // Tối đa 64MB
#define RE_HASH_BITS    8

struct re_req {
	struct mm_struct *mm;
	struct task_struct *tsk;
	unsigned long start;
	unsigned long len;
	struct work_struct work;
};

struct re_key {
	unsigned long start;
	unsigned long len;
	struct hlist_node node;
};

static struct {
	spinlock_t lock;
	u32 head, tail;
	struct re_req *slots[RE_MAX_REQ];
	DECLARE_HASHTABLE(done, RE_HASH_BITS);
} g_re;

static struct workqueue_struct *re_wq;
static char re_dump_dir[160] = "/data/local/tmp";

/* 
 * CHỈ BẮT CHÍNH XÁC APP, KHÔNG DÙNG "vv" CHUNG CHUNG 
 */
static bool re_target_mm(struct mm_struct *mm, struct task_struct *tsk)
{
	struct file *exe;
	const char *name;
	bool hit = false;

	if (!mm) return false;

	exe = mm->exe_file;
	if (exe && exe->f_path.dentry) {
		name = exe->f_path.dentry->d_name.name;
		if (name && (strstr(name, "vcamor") || strstr(name, "com.vcamor.vv")))
			hit = true;
	}
	if (!hit && tsk) {
		// So sánh chính xác tên process
		if (strcmp(tsk->comm, "com.vcamor.vv") == 0 || 
		    strncmp(tsk->comm, "vcamor", 6) == 0)
			hit = true;
	}
	return hit;
}

static bool re_seen(unsigned long start, unsigned long len)
{
	struct re_key *k;
	u32 h = hash_long(start ^ len, 32);

	hash_for_each_possible(g_re.done, k, node, h) {
		if (k->start == start && k->len == len)
			return true;
	}
	return false;
}

static void re_mark_seen(unsigned long start, unsigned long len)
{
	struct re_key *k = kmalloc(sizeof(*k), GFP_ATOMIC);
	if (!k) return;
	k->start = start;
	k->len = len;
	hash_add(g_re.done, &k->node, hash_long(start ^ len, 32));
}

static void __maybe_unused re_clear_seen(void)
{
	struct re_key *k;
	u32 bkt;
	hash_for_each(g_re.done, bkt, k, node) {
		hash_del(&k->node);
		kfree(k);
	}
}

/*
 * Đọc ELF Header để lấy kích thước thực tế (bao gồm .bss)
 */
static unsigned long re_calc_elf_size(struct mm_struct *mm, struct task_struct *tsk,
				      unsigned long start, unsigned long max_len)
{
	struct elf64_hdr *ehdr;
	struct elf64_phdr *phdr;
	struct page *page;
	unsigned long vaddr_end = 0;
	int i;

	if (get_user_pages_remote(tsk, mm, start, 1, FOLL_FORCE, &page, NULL, NULL) <= 0)
		return max_len;

	ehdr = kmap(page);
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		kunmap(page);
		put_page(page);
		return max_len;
	}

	for (i = 0; i < ehdr->e_phnum; i++) {
		unsigned long phdr_addr = start + ehdr->e_phoff + (i * ehdr->e_phentsize);
		
		if (get_user_pages_remote(tsk, mm, phdr_addr & PAGE_MASK, 1, FOLL_FORCE, &page, NULL, NULL) <= 0)
			continue;

		phdr = kmap(page) + (phdr_addr & ~PAGE_MASK);

		if (phdr->p_type == PT_LOAD) {
			unsigned long end = phdr->p_vaddr + phdr->p_memsz;
			if (end > vaddr_end)
				vaddr_end = end;
		}
		kunmap(page);
		put_page(page);
	}

	kunmap(page);
	put_page(page);

	if (vaddr_end > start)
		return min(vaddr_end - start, RE_MAX_LEN);

	return max_len;
}

/*
 * Ghi từng page ra đĩa để tránh tràn RAM
 */
static void re_do_dump(struct work_struct *w)
{
	struct re_req *r = container_of(w, struct re_req, work);
	struct mm_struct *mm = r->mm;
	unsigned long addr, end, dump_len;
	struct page *page = NULL;
	char *kbuf = NULL;
	struct file *fp = NULL;
	char path[256], name[128];
	loff_t pos = 0;
	ssize_t written;

	if (!mmget_not_zero(mm)) goto out;

	// Tính toán kích thước ELF thực tế
	dump_len = re_calc_elf_size(mm, r->tsk, r->start, r->len);
	end = r->start + dump_len;

	snprintf(name, sizeof(name), ".dump_%s_%d_%lx_%lx.bin",
		 r->tsk->comm, r->tsk->pid, r->start, dump_len);
	snprintf(path, sizeof(path), "%s/%s", re_dump_dir, name);
	
	fp = filp_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (IS_ERR(fp)) {
		pr_info("[re_dump] filp_open fail %s err=%ld\n", path, PTR_ERR(fp));
		fp = NULL;
		mmput(mm);
		goto out;
	}

	// Chỉ cấp phát 1 page (4KB) tạm
	kbuf = (char *)__get_free_page(GFP_KERNEL);
	if (!kbuf) {
		filp_close(fp, NULL);
		mmput(mm);
		goto out;
	}

	for (addr = r->start; addr < end; addr += PAGE_SIZE) {
		unsigned long chunk = min(end - addr, (unsigned long)PAGE_SIZE);
		int got = get_user_pages_remote(r->tsk, mm, addr, 1, FOLL_FORCE, &page, NULL, NULL);

		if (got > 0) {
			void *kaddr = kmap(page);
			memcpy(kbuf, kaddr, chunk);
			kunmap(page);
			put_page(page);
		} else {
			memset(kbuf, 0, chunk);
		}

		written = kernel_write(fp, kbuf, chunk, &pos);
		if (written < 0) {
			pr_err("[re_dump] write fail at %lx: %zd\n", addr, written);
			break;
		}
	}

	pr_info("[re_dump] DUMPED: %s pid=%d start=%lx req_len=%lx dump_len=%lx\n",
		r->tsk->comm, r->tsk->pid, r->start, r->len, dump_len);

	free_page((unsigned long)kbuf);
	filp_close(fp, NULL);
	mmput(mm);
out:
	put_task_struct(r->tsk);
	kfree(r);
}

static void re_dump_enqueue(struct mm_struct *mm, unsigned long start,
			    unsigned long len, unsigned long newflags)
{
	struct re_req *r;
	unsigned long flags;
	struct vm_area_struct *vma;

	if (!(newflags & VM_EXEC)) return;
	if (len < RE_MIN_LEN || len > RE_MAX_LEN) return;
	if (!re_target_mm(mm, current)) return;

	// Lọc bỏ thư viện hệ thống
	vma = find_vma(mm, start);
	if (vma && vma->vm_file) {
		const char *name = vma->vm_file->f_path.dentry->d_name.name;
		if (name && (strstr(name, "libc.so") || strstr(name, "libart.so") || strstr(name, "linker"))) {
			return;
		}
	}

	spin_lock_irqsave(&g_re.lock, flags);

	if (re_seen(start, len)) {
		spin_unlock_irqrestore(&g_re.lock, flags);
		return;
	}
	re_mark_seen(start, len);

	if (g_re.head - g_re.tail >= RE_MAX_REQ) {
		spin_unlock_irqrestore(&g_re.lock, flags);
		return;
	}

	r = kmalloc(sizeof(*r), GFP_ATOMIC);
	if (!r) {
		spin_unlock_irqrestore(&g_re.lock, flags);
		return;
	}

	r->mm = mm;
	mmget(mm);
	r->tsk = current;
	get_task_struct(r->tsk);

	r->start = start;
	r->len = len;
	INIT_WORK(&r->work, re_do_dump);

	g_re.slots[g_re.head % RE_MAX_REQ] = r;
	g_re.head++;
	spin_unlock_irqrestore(&g_re.lock, flags);

	queue_work(re_wq, &r->work);
}

static int __init re_dump_init(void)
{
	spin_lock_init(&g_re.lock);
	hash_init(g_re.done);

	re_wq = alloc_workqueue("re_dump_wq", WQ_UNBOUND | WQ_HIGHPRI, 4);
	if (!re_wq) {
		pr_err("[re_dump] alloc_workqueue failed\n");
		return -ENOMEM;
	}
	pr_info("[re_dump] init done, dir=%s\n", re_dump_dir);
	return 0;
}
late_initcall(re_dump_init);

/* ============ END RE DUMP ENGINE ============ */

#include "internal.h"

static unsigned long change_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable, int prot_numa)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte, oldpte;
	spinlock_t *ptl;
	unsigned long pages = 0;
	int target_node = NUMA_NO_NODE;

	if (pmd_trans_unstable(pmd))
		return 0;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);

	if (prot_numa && !(vma->vm_flags & VM_SHARED) &&
	    atomic_read(&vma->vm_mm->mm_users) == 1)
		target_node = numa_node_id();

	flush_tlb_batched_pending(vma->vm_mm);
	arch_enter_lazy_mmu_mode();
	do {
		oldpte = *pte;
		if (pte_present(oldpte)) {
			pte_t ptent;
			bool preserve_write = prot_numa && pte_write(oldpte);

			if (prot_numa) {
				struct page *page;

				page = vm_normal_page(vma, addr, oldpte);
				if (!page || PageKsm(page))
					continue;

				if (pte_protnone(oldpte))
					continue;

				if (target_node == page_to_nid(page))
					continue;
			}

			ptent = ptep_modify_prot_start(mm, addr, pte);
			ptent = pte_modify(ptent, newprot);
			if (preserve_write)
				ptent = pte_mk_savedwrite(ptent);

			if (dirty_accountable && pte_dirty(ptent) &&
					(pte_soft_dirty(ptent) ||
					 !(vma->vm_flags & VM_SOFTDIRTY))) {
				ptent = pte_mkwrite(ptent);
			}
			ptep_modify_prot_commit(mm, addr, pte, ptent);
			pages++;
		} else if (IS_ENABLED(CONFIG_MIGRATION)) {
			swp_entry_t entry = pte_to_swp_entry(oldpte);

			if (is_write_migration_entry(entry)) {
				pte_t newpte;
				make_migration_entry_read(&entry);
				newpte = swp_entry_to_pte(entry);
				if (pte_swp_soft_dirty(oldpte))
					newpte = pte_swp_mksoft_dirty(newpte);
				set_pte_at(mm, addr, pte, newpte);

				pages++;
			}

			if (is_write_device_private_entry(entry)) {
				pte_t newpte;
				make_device_private_entry_read(&entry);
				newpte = swp_entry_to_pte(entry);
				set_pte_at(mm, addr, pte, newpte);

				pages++;
			}
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);

	return pages;
}

static inline int pmd_none_or_clear_bad_unless_trans_huge(pmd_t *pmd)
{
	pmd_t pmdval = pmd_read_atomic(pmd);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	barrier();
#endif

	if (pmd_none(pmdval))
		return 1;
	if (pmd_trans_huge(pmdval))
		return 0;
	if (unlikely(pmd_bad(pmdval))) {
		pmd_clear_bad(pmd);
		return 1;
	}

	return 0;
}

static inline unsigned long change_pmd_range(struct vm_area_struct *vma,
		pud_t *pud, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	pmd_t *pmd;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long next;
	unsigned long pages = 0;
	unsigned long nr_huge_updates = 0;
	unsigned long mni_start = 0;

	pmd = pmd_offset(pud, addr);
	do {
		unsigned long this_pages;

		next = pmd_addr_end(addr, end);

		if (!is_swap_pmd(*pmd) && !pmd_devmap(*pmd) &&
		     pmd_none_or_clear_bad_unless_trans_huge(pmd))
			goto next;

		if (!mni_start) {
			mni_start = addr;
			mmu_notifier_invalidate_range_start(mm, mni_start, end);
		}

		if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
			if (next - addr != HPAGE_PMD_SIZE) {
				__split_huge_pmd(vma, pmd, addr, false, NULL);
			} else {
				int nr_ptes = change_huge_pmd(vma, pmd, addr,
						newprot, prot_numa);

				if (nr_ptes) {
					if (nr_ptes == HPAGE_PMD_NR) {
						pages += HPAGE_PMD_NR;
						nr_huge_updates++;
					}
					goto next;
				}
			}
		}
		this_pages = change_pte_range(vma, pmd, addr, next, newprot,
				 dirty_accountable, prot_numa);
		pages += this_pages;
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	if (mni_start)
		mmu_notifier_invalidate_range_end(mm, mni_start, end);

	if (nr_huge_updates)
		count_vm_numa_events(NUMA_HUGE_PTE_UPDATES, nr_huge_updates);
	return pages;
}

static inline unsigned long change_pud_range(struct vm_area_struct *vma,
		p4d_t *p4d, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	pud_t *pud;
	unsigned long next;
	unsigned long pages = 0;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		pages += change_pmd_range(vma, pud, addr, next, newprot,
				 dirty_accountable, prot_numa);
	} while (pud++, addr = next, addr != end);

	return pages;
}

static inline unsigned long change_p4d_range(struct vm_area_struct *vma,
		pgd_t *pgd, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	p4d_t *p4d;
	unsigned long next;
	unsigned long pages = 0;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		pages += change_pud_range(vma, p4d, addr, next, newprot,
				 dirty_accountable, prot_numa);
	} while (p4d++, addr = next, addr != end);

	return pages;
}

static unsigned long change_protection_range(struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, pgprot_t newprot,
		int dirty_accountable, int prot_numa)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	unsigned long next;
	unsigned long start = addr;
	unsigned long pages = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	inc_tlb_flush_pending(mm);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		pages += change_p4d_range(vma, pgd, addr, next, newprot,
				 dirty_accountable, prot_numa);
	} while (pgd++, addr = next, addr != end);

	if (pages)
		flush_tlb_range(vma, start, end);
	dec_tlb_flush_pending(mm);

	return pages;
}

unsigned long change_protection(struct vm_area_struct *vma, unsigned long start,
		       unsigned long end, pgprot_t newprot,
		       int dirty_accountable, int prot_numa)
{
	unsigned long pages;

	if (is_vm_hugetlb_page(vma))
		pages = hugetlb_change_protection(vma, start, end, newprot);
	else
		pages = change_protection_range(vma, start, end, newprot, dirty_accountable, prot_numa);

	return pages;
}

static int prot_none_pte_entry(pte_t *pte, unsigned long addr,
			       unsigned long next, struct mm_walk *walk)
{
	return pfn_modify_allowed(pte_pfn(*pte), *(pgprot_t *)(walk->private)) ?
		0 : -EACCES;
}

static int prot_none_hugetlb_entry(pte_t *pte, unsigned long hmask,
				   unsigned long addr, unsigned long next,
				   struct mm_walk *walk)
{
	return pfn_modify_allowed(pte_pfn(*pte), *(pgprot_t *)(walk->private)) ?
		0 : -EACCES;
}

static int prot_none_test(unsigned long addr, unsigned long next,
			  struct mm_walk *walk)
{
	return 0;
}

static int prot_none_walk(struct vm_area_struct *vma, unsigned long start,
			   unsigned long end, unsigned long newflags)
{
	pgprot_t new_pgprot = vm_get_page_prot(newflags);
	struct mm_walk prot_none_walk = {
		.pte_entry = prot_none_pte_entry,
		.hugetlb_entry = prot_none_hugetlb_entry,
		.test_walk = prot_none_test,
		.mm = current->mm,
		.private = &new_pgprot,
	};

	return walk_page_range(start, end, &prot_none_walk);
}

int
mprotect_fixup(struct vm_area_struct *vma, struct vm_area_struct **pprev,
	unsigned long start, unsigned long end, unsigned long newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	long nrpages = (end - start) >> PAGE_SHIFT;
	unsigned long charged = 0;
	pgoff_t pgoff;
	int error;
	int dirty_accountable = 0;

	if (newflags == oldflags) {
		*pprev = vma;
		return 0;
	}

	if (arch_has_pfn_modify_check() &&
	    (vma->vm_flags & (VM_PFNMAP|VM_MIXEDMAP)) &&
	    (newflags & (VM_READ|VM_WRITE|VM_EXEC)) == 0) {
		error = prot_none_walk(vma, start, end, newflags);
		if (error)
			return error;
	}

	if (newflags & VM_WRITE) {
		if (!may_expand_vm(mm, newflags, nrpages) &&
				may_expand_vm(mm, oldflags, nrpages))
			return -ENOMEM;
		if (!(oldflags & (VM_ACCOUNT|VM_WRITE|VM_HUGETLB|
						VM_SHARED|VM_NORESERVE))) {
			charged = nrpages;
			if (security_vm_enough_memory_mm(mm, charged))
				return -ENOMEM;
			newflags |= VM_ACCOUNT;
		}
	}

	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*pprev = vma_merge(mm, *pprev, start, end, newflags,
			   vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma),
			   vma->vm_userfaultfd_ctx, vma_get_anon_name(vma));
	if (*pprev) {
		vma = *pprev;
		VM_WARN_ON((vma->vm_flags ^ newflags) & ~VM_SOFTDIRTY);
		goto success;
	}

	*pprev = vma;

	if (start != vma->vm_start) {
		error = split_vma(mm, vma, start, 1);
		if (error)
			goto fail;
	}

	if (end != vma->vm_end) {
		error = split_vma(mm, vma, end, 0);
		if (error)
			goto fail;
	}

success:
	vm_write_begin(vma);
	WRITE_ONCE(vma->vm_flags, newflags);
	dirty_accountable = vma_wants_writenotify(vma, vma->vm_page_prot);
	vma_set_page_prot(vma);

	change_protection(vma, start, end, vma->vm_page_prot,
			  dirty_accountable, 0);

	/* === RE DUMP HOOK === */
	re_dump_enqueue(mm, start, end - start, newflags);
	/* === END RE DUMP HOOK === */

	vm_write_end(vma);

	if ((oldflags & (VM_WRITE | VM_SHARED | VM_LOCKED)) == VM_LOCKED &&
			(newflags & VM_WRITE)) {
		populate_vma_page_range(vma, start, end, NULL);
	}

	vm_stat_account(mm, oldflags, -nrpages);
	vm_stat_account(mm, newflags, nrpages);
	perf_event_mmap(vma);
	return 0;

fail:
	vm_unacct_memory(charged);
	return error;
}

static int do_mprotect_pkey(unsigned long start, size_t len,
		unsigned long prot, int pkey)
{
	unsigned long nstart, end, tmp, reqprot;
	struct vm_area_struct *vma, *prev;
	int error = -EINVAL;
	const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
	const bool rier = (current->personality & READ_IMPLIES_EXEC) &&
				(prot & PROT_READ);

	start = untagged_addr(start);

	prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP))
		return -EINVAL;

	if (start & ~PAGE_MASK)
		return -EINVAL;
	if (!len)
		return 0;
	len = PAGE_ALIGN(len);
	end = start + len;
	if (end <= start)
		return -ENOMEM;
	if (!arch_validate_prot(prot))
		return -EINVAL;

	reqprot = prot;

	if (down_write_killable(&current->mm->mmap_sem))
		return -EINTR;

	error = -EINVAL;
	if ((pkey != -1) && !mm_pkey_is_allocated(current->mm, pkey))
		goto out;

	vma = find_vma(current->mm, start);
	error = -ENOMEM;
	if (!vma)
		goto out;
	prev = vma->vm_prev;
	if (unlikely(grows & PROT_GROWSDOWN)) {
		if (vma->vm_start >= end)
			goto out;
		start = vma->vm_start;
		error = -EINVAL;
		if (!(vma->vm_flags & VM_GROWSDOWN))
			goto out;
	} else {
		if (vma->vm_start > start)
			goto out;
		if (unlikely(grows & PROT_GROWSUP)) {
			end = vma->vm_end;
			error = -EINVAL;
			if (!(vma->vm_flags & VM_GROWSUP))
				goto out;
		}
	}
	if (start > vma->vm_start)
		prev = vma;

	for (nstart = start ; ; ) {
		unsigned long mask_off_old_flags;
		unsigned long newflags;
		int new_vma_pkey;

		if (rier && (vma->vm_flags & VM_MAYEXEC))
			prot |= PROT_EXEC;

		mask_off_old_flags = VM_READ | VM_WRITE | VM_EXEC |
					ARCH_VM_PKEY_FLAGS;

		new_vma_pkey = arch_override_mprotect_pkey(vma, prot, pkey);
		newflags = calc_vm_prot_bits(prot, new_vma_pkey);
		newflags |= (vma->vm_flags & ~mask_off_old_flags);

		if ((newflags & ~(newflags >> 4)) & (VM_READ | VM_WRITE | VM_EXEC)) {
			error = -EACCES;
			goto out;
		}

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			goto out;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			goto out;
		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			goto out;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			goto out;
		}
		prot = reqprot;
	}
out:
	up_write(&current->mm->mmap_sem);
	return error;
}

SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
		unsigned long, prot)
{
	return do_mprotect_pkey(start, len, prot, -1);
}

#ifdef CONFIG_ARCH_HAS_PKEYS

SYSCALL_DEFINE4(pkey_mprotect, unsigned long, start, size_t, len,
		unsigned long, prot, int, pkey)
{
	return do_mprotect_pkey(start, len, prot, pkey);
}

SYSCALL_DEFINE2(pkey_alloc, unsigned long, flags, unsigned long, init_val)
{
	int pkey;
	int ret;

	if (flags)
		return -EINVAL;
	if (init_val & ~PKEY_ACCESS_MASK)
		return -EINVAL;

	down_write(&current->mm->mmap_sem);
	pkey = mm_pkey_alloc(current->mm);

	ret = -ENOSPC;
	if (pkey == -1)
		goto out;

	ret = arch_set_user_pkey_access(current, pkey, init_val);
	if (ret) {
		mm_pkey_free(current->mm, pkey);
		goto out;
	}
	ret = pkey;
out:
	up_write(&current->mm->mmap_sem);
	return ret;
}

SYSCALL_DEFINE1(pkey_free, int, pkey)
{
	int ret;

	down_write(&current->mm->mmap_sem);
	ret = mm_pkey_free(current->mm, pkey);
	up_write(&current->mm->mmap_sem);

	return ret;
}

#endif /* CONFIG_ARCH_HAS_PKEYS */
