// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * This file is not compiled stand-alone. It is includes directly in the
 * sev-es.c and sev-snp.c.
 */

static inline u64 sev_es_rd_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}
