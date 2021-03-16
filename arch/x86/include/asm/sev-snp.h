/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD SEV Secure Nested Paging Support
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __ASM_SECURE_NESTED_PAGING_H
#define __ASM_SECURE_NESTED_PAGING_H

#ifndef __ASSEMBLY__
#include <asm/irqflags.h> /* native_save_fl() */

/* Return code of __pvalidate */
#define PVALIDATE_SUCCESS		0
#define PVALIDATE_FAIL_INPUT		1
#define PVALIDATE_FAIL_SIZEMISMATCH	6

/* RMP page size */
#define RMP_PG_SIZE_2M			1
#define RMP_PG_SIZE_4K			0

/* Page State Change MSR Protocol */
#define GHCB_SNP_PAGE_STATE_CHANGE_REQ	0x0014
#define		GHCB_SNP_PAGE_STATE_REQ_GFN(v, o)	(GHCB_SNP_PAGE_STATE_CHANGE_REQ | \
							 ((unsigned long)((o) & 0xf) << 52) | \
							 (((v) << 12) & 0xffffffffffffff))
#define	SNP_PAGE_STATE_PRIVATE		1
#define	SNP_PAGE_STATE_SHARED		2
#define	SNP_PAGE_STATE_PSMASH		3
#define	SNP_PAGE_STATE_UNSMASH		4

#define GHCB_SNP_PAGE_STATE_CHANGE_RESP	0x0015
#define		GHCB_SNP_PAGE_STATE_RESP_VAL(val)	((val) >> 32)

/* Page State Change NAE event */
#define SNP_PAGE_STATE_CHANGE_MAX_ENTRY		253
struct __packed snp_page_state_header {
	uint16_t cur_entry;
	uint16_t end_entry;
	uint32_t reserved;
};

struct __packed snp_page_state_entry {
	uint64_t cur_page:12;
	uint64_t gfn:40;
	uint64_t operation:4;
	uint64_t pagesize:1;
	uint64_t reserved:7;
};

struct __packed snp_page_state_change {
	struct snp_page_state_header header;
	struct snp_page_state_entry entry[SNP_PAGE_STATE_CHANGE_MAX_ENTRY];
};

/* GHCB GPA register */
#define GHCB_REGISTER_GPA_REQ	0x012UL
#define		GHCB_REGISTER_GPA_REQ_VAL(v)		(GHCB_REGISTER_GPA_REQ | ((v) << 12))

#define GHCB_REGISTER_GPA_RESP	0x013UL
#define		GHCB_REGISTER_GPA_RESP_VAL(val)		((val) >> 12)

/* Macro to convert the x86 page level to the RMP level and vice versa */
#define X86_RMP_PG_LEVEL(level)	(((level) == PG_LEVEL_4K) ? RMP_PG_SIZE_4K : RMP_PG_SIZE_2M)
#define RMP_X86_PG_LEVEL(level)	(((level) == RMP_PG_SIZE_4K) ? PG_LEVEL_4K : PG_LEVEL_2M)

#ifdef CONFIG_AMD_MEM_ENCRYPT
static inline int __pvalidate(unsigned long vaddr, int rmp_psize, int validate,
			      unsigned long *rflags)
{
	unsigned long flags;
	int rc;

	asm volatile(".byte 0xF2, 0x0F, 0x01, 0xFF\n\t"
		     "pushf; pop %0\n\t"
		     : "=rm"(flags), "=a"(rc)
		     : "a"(vaddr), "c"(rmp_psize), "d"(validate)
		     : "memory", "cc");

	*rflags = flags;
	return rc;
}

void sev_snp_issue_pvalidate(unsigned long vaddr, unsigned int npages, bool validate);

union sev_rmp_adjust
{
    u64 as_uint64;
    struct
    {
        u64 target_vmpl : 8;
        u64 enable_read : 1;
        u64 enable_write : 1;
        u64 enable_user_execute : 1;
        u64 enable_kernel_execute : 1;
        u64 reserved1 : 4;
        u64 vmsa : 1;
    };
};

#define RMPADJUST(addr, size, flags, ret) \
	asm volatile ("movq %1, %%rax\n\t" \
		      "mov %2, %%ecx\n\t" \
		      "movq %3, %%rdx\n\t" \
		      ".byte 0xf3, 0x0f, 0x01, 0xfe\n\t" \
		      "movq %%rax, %0" \
			: "=r" (ret) \
			: "r" (addr), "r" (size), "r" (flags) \
			: "rax", "rcx", "rdx")

void sev_snp_register_ghcb(unsigned long paddr);

void __init early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
		unsigned int npages);
void __init early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
		unsigned int npages);
int snp_set_memory_shared(unsigned long vaddr, unsigned int npages);
int snp_set_memory_private(unsigned long vaddr, unsigned int npages);

void sev_snp_setup_hv_doorbell_page(struct ghcb *ghcb);

#else	/* !CONFIG_AMD_MEM_ENCRYPT */

static inline int __pvalidate(unsigned long vaddr, int psize, int validate, unsigned long *eflags)
{
	return 0;
}

static inline void sev_snp_register_ghcb(unsigned long paddr) { }

static inline void __init
early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr, unsigned int npages)
{
	return 0;
}
static inline void __init
early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr, unsigned int npages)
{
	return 0;
}
static inline int snp_set_memory_shared(unsigned long vaddr, unsigned int npages) { return 0; }
static inline int snp_set_memory_private(unsigned long vaddr, unsigned int npages) { return 0; }

static inline void sev_snp_setup_hv_doorbell_page(struct ghcb *ghcb) { return; }

#endif /* CONFIG_AMD_MEM_ENCRYPT */

#endif	/* __ASSEMBLY__ */
#endif  /* __ASM_SECURE_NESTED_PAGING_H */
