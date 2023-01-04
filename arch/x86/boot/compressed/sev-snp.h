/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD SEV Secure Nested Paging Support
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#ifndef __COMPRESSED_SECURE_NESTED_PAGING_H
#define __COMPRESSED_SECURE_NESTED_PAGING_H

#ifdef CONFIG_AMD_MEM_ENCRYPT

void sev_snp_set_page_private(unsigned long paddr);
void sev_snp_set_page_shared(unsigned long paddr);

#else

static inline void sev_snp_set_page_private(unsigned long paddr) { }
static inline void sev_snp_set_page_shared(unsigned long paddr) { }

#endif /* CONFIG_AMD_MEM_ENCRYPT */

#endif /* __COMPRESSED_SECURE_NESTED_PAGING_H */
