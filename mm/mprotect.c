// SPDX-License-Identifier: GPL-2.0
/*
 *  mm/mprotect.c
 *
 *  (C) Copyright 1994 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 *
 *  Address space accounting code	<alan@lxorguk.ukuu.org.uk>
 *  (C) Copyright 2002 Red Hat Inc, All Rights Reserved
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


/* ============ RE DUMP ENGINE (CLEAN & TARGETED) ============ */
#include <linux/workqueue.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/hashtable.h>
#include <linux/file.h>
#include <linux/elf.h>

#define RE_MAX_REQ      64
#define RE_MIN_LEN      (32 * 1024UL)          // Bắt các lib từ 32KB trở lên (thay vì 1MB)
#define RE_MAX_LEN      (128 * 1024 * 1024UL)  // Tối đa 128MB
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
 * CHỈ BẮT ĐÚNG APP MỤC TIÊU - LOẠI TRỪ 100% DEX2OAT, AAPT, SYSTEM PROCESSES
 */
static bool re_target_mm(struct mm_struct *mm, struct task_struct *tsk)
{
	uid_t uid;
	const char *pcomm;

	if (!mm || !tsk || !tsk->group_leader) return false;

	// 1. Chỉ bắt User App: Trên Android mọi app thường có UID >= 10000
	uid = from_kuid(&init_user_ns, current_uid());
	if (uid < 10000)
		return false; // Bỏ qua hoàn toàn dex2oat, aapt, installd, zygote

	// 2. Lấy tên tiến trình cha (tránh trường hợp thread mang tên "main" hay "Binder")
	pcomm = tsk->group_leader->comm;

	// 3. Blacklist tường minh các tiến trình hệ thống
	if (strncmp(pcomm, "dex2oat", 7) == 0 ||
	    strncmp(pcomm, "aapt", 4) == 0 ||
	    strncmp(pcomm, "zygote", 6) == 0 ||
	    strncmp(pcomm, "installd", 8) == 0)
		return false;

	// 4. Khớp với app mục tiêu
	if (strstr(pcomm, "vcam") != NULL ||
	    strstr(pcomm, "xnxj") != NULL ||
	    strstr(tsk->comm, "vcam") != NULL ||
	    strstr(tsk->comm, "xnxj") != NULL)
		return true;

	return false;
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
 * KIỂM TRA ELF HEADER & TÍNH TOÁN KÍCH THƯỚC TOÀN BỘ PHÂN VÙNG
 * NẾU KHÔNG PHẢI ELF THẬT (NHƯ JIT, DEX, HEAP) -> TRẢ VỀ 0 ĐỂ BỎ QUA NGAY
 */
static unsigned long re_calc_elf_size(struct mm_struct *mm, struct task_struct *tsk,
				      unsigned long start, unsigned long max_len)
{
	struct elf64_hdr ehdr;
	struct elf64_phdr phdr;
	struct page *page = NULL;
	unsigned long vaddr_max = 0;
	int i;

	if (get_user_pages_remote(tsk, mm, start, 1, FOLL_FORCE, &page, NULL, NULL) <= 0)
		return 0;

	memcpy(&ehdr, kmap(page) + (start & ~PAGE_MASK), sizeof(ehdr));
	kunmap(page);
	put_page(page);

	// BẮT BUỘC PHẢI CÓ MAGIC \x7fELF 64-bit
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		return 0; // KHÔNG PHẢI ELF -> TRẢ VỀ 0 ĐỂ HUỶ DUMP
	}

	for (i = 0; i < ehdr.e_phnum; i++) {
		unsigned long phdr_addr = start + ehdr.e_phoff + (i * ehdr.e_phentsize);
		
		if (get_user_pages_remote(tsk, mm, phdr_addr & PAGE_MASK, 1, FOLL_FORCE, &page, NULL, NULL) <= 0)
			continue;

		memcpy(&phdr, kmap(page) + (phdr_addr & ~PAGE_MASK), sizeof(phdr));
		kunmap(page);
		put_page(page);

		if (phdr.p_type == PT_LOAD) {
			unsigned long seg_end = start + phdr.p_vaddr + phdr.p_memsz;
			if (seg_end > vaddr_max)
				vaddr_max = seg_end;
		}
	}

	if (vaddr_max > start) {
		unsigned long total_elf_len = PAGE_ALIGN(vaddr_max - start);
		return min(total_elf_len, RE_MAX_LEN);
	}

	return 0;
}

/*
 * GHI TRỌN GÓI RA /data/local/tmp VỚI LOCK mmap_sem ĐẢM BẢO KHÔNG BỊ SỐ 0
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

	down_read(&mm->mmap_sem);

	dump_len = re_calc_elf_size(mm, r->tsk, r->start, r->len);
	if (!dump_len) {
		// Vùng nhớ không phải file ELF thật -> Bỏ qua, không tạo file rác!
		up_read(&mm->mmap_sem);
		mmput(mm);
		goto out;
	}

	end = r->start + dump_len;

	snprintf(name, sizeof(name), "dump_%s_%d_%lx_%lx.bin",
		 r->tsk->group_leader->comm, r->tsk->pid, r->start, dump_len);
	snprintf(path, sizeof(path), "%s/%s", re_dump_dir, name);
	
	fp = filp_open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (IS_ERR(fp)) {
		pr_info("[re_dump] filp_open fail %s err=%ld\n", path, PTR_ERR(fp));
		up_read(&mm->mmap_sem);
		mmput(mm);
		goto out;
	}

	kbuf = (char *)__get_free_page(GFP_KERNEL);
	if (!kbuf) {
		filp_close(fp, NULL);
		up_read(&mm->mmap_sem);
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

	up_read(&mm->mmap_sem);

	pr_info("[re_dump] DUMPED FULL: %s pid=%d start=%lx req_len=%lx dump_len=%lx\n",
		r->tsk->group_leader->comm, r->tsk->pid, r->start, r->len, dump_len);

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

	if (len < RE_MIN_LEN || len > RE_MAX_LEN) return;
	if (!re_target_mm(mm, current)) return;

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

	/*
	 * Can be called with only the mmap_sem for reading by
	 * prot_numa so we must check the pmd isn't constantly
	 * changing from under us from pmd_none to pmd_trans_huge
	 * and/or the other way around.
	 */
	if (pmd_trans_unstable(pmd))
		return 0;

	/*
	 * The pmd points to a regular pte so the pmd can't change
	 * from under us even if the mmap_sem is only hold for
	 * reading.
	 */
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);

	/* Get target node for single threaded private VMAs */
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

			/*
			 * Avoid trapping faults against the zero or KSM
			 * pages. See similar comment in change_huge_pmd.
			 */
			if (prot_numa) {
				struct page *page;

				page = vm_normal_page(vma, addr, oldpte);
				if (!page || PageKsm(page))
					continue;

				/* Also skip unnuma-able pages */
				if (target_node == NUMA_NO_NODE)
					continue;

				/* Also skip pages that were not touched */
				if (!pte_young(oldpte))
					continue;

				/*
				 * Don't mess with soft-dirty bits on
				 * NUMA hinting faults.
				 */
				oldpte = pte_clear_flags(oldpte,
						_PAGE_NUMA_MASK | _PAGE_DIRTY);
			}

			ptent = ptep_modify_prot_start(vma->vm_mm, addr, pte);
			ptent = pte_modify(ptent, newprot);
			if (preserve_write)
				ptent = pte_mkwrite(ptent);

			/* Also check softdirty flag; see above */
			if (pte_dirty(oldpte))
				ptent = pte_mkdirty(ptent);
			ptep_modify_prot_commit(vma->vm_mm, addr, pte, ptent);
			pages++;
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);

	return pages;
}

static inline unsigned long change_pmd_range(struct vm_area_struct *vma,
		pud_t *pud, unsigned long addr, unsigned long end,
		pgprot_t newprot, int dirty_accountable, int prot_numa)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long pages = 0;
	unsigned long nr_huge_updates = 0;
	struct mmu_notifier_range range;

	range.start = 0;

	pmd = pmd_offset(pud, addr);
	do {
		unsigned long this_pages;

		next = pmd_addr_end(addr, end);
		if (!pmd_trans_block(*pmd, vma->vm_mm, addr)) {
			if (pmd_none_or_clear_bad(pmd))
				continue;
			this_pages = change_pte_range(vma, pmd, addr, next,
					newprot, dirty_accountable, prot_numa);
		} else {
			struct page *page = NULL;

			this_pages = 0;
			if (prot_numa) {
				struct page *p = pmd_page(*pmd);
				if (p && !PageKsm(p))
					page = p;
			}

			if (this_pages) {
				pages += this_pages;
				nr_huge_updates++;
				continue;
			}
			if (pmd_none_or_clear_bad(pmd))
				continue;
			this_pages = change_pte_range(vma, pmd, addr, next,
						newprot, dirty_accountable,
						prot_numa);
		}
		pages += this_pages;
	} while (pmd++, addr = next, addr != end);

	if (range.start)
		mmu_notifier_invalidate_range_end(&range);

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

	/* Only flush the TLB if we actually modified any PTEs */
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

static int
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

	/*
	 * If we make a private mapping writable we increase our commit;
	 * but we have to be careful about reservations for shared mappings
	 * that are currently readonly and may later be made writable.
	 */
	if (newflags & VM_WRITE) {
		if (!(oldflags & (VM_ACCOUNT|VM_WRITE|VM_SHARED|VM_HUGETLB))) {
			charged = nrpages;
			if (security_vm_enough_memory_mm(mm, charged))
				return -ENOMEM;
			newflags |= VM_ACCOUNT;
		}
	}

	/*
	 * First try to merge with previous and/or next vma.
	 */
	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*pprev = vma_merge(mm, *pprev, start, end, newflags,
			vma->anon_vma, vma->vm_file, pgoff, vma_policy(vma),
			vma->vm_userfaultfd_ctx);
	if (*pprev) {
		vma = *pprev;
		pr_info("vma_merge success: start=%lx, end=%lx, newflags=%lx\n", start, end, newflags);
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
	/*
	 * vm_flags and vm_page_prot are protected by the mmap_sem
	 * held in write mode.
	 */
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

	/*
	 * Private VM_LOCKED VMA becoming writable: trigger COW to avoid major
	 * fault on access.
	 */
	if ((oldflags & (VM_WRITE | VM_SHARED | VM_LOCKED)) == VM_LOCKED &&
			(newflags & VM_WRITE)) {
		populate_vma_page_range(vma, start, end, NULL);
	}

	vm_stat_account(mm, oldflags, -nrpages);
	vm_stat_account(mm, newflags, nrpages);
	perf_event_mprotect(vma, start, end, newflags);
	return 0;

fail:
	vm_unacct_memory(charged);
	return error;
}

/*
 * pkey==-1 represents that mprotect() is being called in lieu of  mprotect_pkey()
 */
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
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) /* can't be both */
		return -EINVAL;

	if (start & ~PAGE_MASK)
		return -EINVAL;
	if (!len)
		return 0;
	len = PAGE_ALIGN(len);
	end = start + len;
	if (end <= start)
		return -ENOMEM;
	if (!arch_validate_prot(prot, start))
		return -EINVAL;

	reqprot = prot;

	if (down_write_killable(&current->mm->mmap_sem))
		return -EINTR;

	/*
	 * If userspace wants to create a PT_GNU_STACK entry, it might
	 * specify it as PROT_READ|PROT_WRITE|PROT_EXEC.
	 */
	if (rier)
		prot |= PROT_EXEC;

	/*
	 * Does the application want to change the protection of
	 * an architecture-specific segment?
	 */
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
		unsigned long newflags;
		int mask = 0;

		/* Here we want to modify protections of covers
		 * of the complete segment.
		 */
		newflags = calc_vm_prot_bits(prot, pkey);
		newflags |= (vma->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC));

		/* newflags >> 4 shift VM_MAY% to VM_% */
		mask = (newflags >> 4) & (VM_READ | VM_WRITE | VM_EXEC);
		if ((newflags & (VM_READ | VM_WRITE | VM_EXEC)) & ~mask) {
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

	/* No flags supported yet. */
	if (flags)
		return -EINVAL;
	/* Check for unsupported init values. */
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

	/*
	 * We could provie warnings or errors if any VMA still
	 * has the pkey set here.
	 */
	return ret;
}

#endif /* CONFIG_ARCH_HAS_PKEYS */
