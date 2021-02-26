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

#else	/* !CONFIG_AMD_MEM_ENCRYPT */

static inline int __pvalidate(unsigned long vaddr, int psize, int validate, unsigned long *eflags)
{
	return 0;
}

#endif /* CONFIG_AMD_MEM_ENCRYPT */

#endif	/* __ASSEMBLY__ */
#endif  /* __ASM_SECURE_NESTED_PAGING_H */
