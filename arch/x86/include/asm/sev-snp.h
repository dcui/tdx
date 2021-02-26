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
