// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2021 Advanced Micro Devices
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#define pr_fmt(fmt)	"SEV-SNP: " fmt

#include <linux/mem_encrypt.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/svm.h>
#include <asm/sev-snp.h>

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

/* Provides sev_es_terminate() */
#include "sev-shared.c"

void sev_snp_register_ghcb(unsigned long paddr)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 old, val;

	/* save the old GHCB MSR */
	old = sev_es_rd_ghcb_msr();

	/* Issue VMGEXIT */
	sev_es_wr_ghcb_msr(GHCB_REGISTER_GPA_REQ_VAL(pfn));
	VMGEXIT();

	val = sev_es_rd_ghcb_msr();

	/* If the response GPA is not ours then abort the guest */
	if ((GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_REGISTER_GPA_RESP) ||
	    (GHCB_REGISTER_GPA_RESP_VAL(val) != pfn))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(old);
}

static void sev_snp_issue_pvalidate(unsigned long vaddr, unsigned int npages, bool validate)
{
	unsigned long eflags, vaddr_end, vaddr_next;
	int rc;

	vaddr = vaddr & PAGE_MASK;
	vaddr_end = vaddr + (npages << PAGE_SHIFT);

	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		rc = __pvalidate(vaddr, RMP_PG_SIZE_4K, validate, &eflags);

		if (rc) {
			pr_err("Failed to validate address 0x%lx ret %d\n", vaddr, rc);
			goto e_fail;
		}

		/* Check for the double validation condition */
		if (eflags & X86_EFLAGS_CF) {
			pr_err("Double %salidation detected (address 0x%lx)\n",
					validate ? "v" : "inv", vaddr);
			goto e_fail;
		}

		vaddr_next = vaddr + PAGE_SIZE;
	}

	return;

e_fail:
	/* Dump stack for the debugging purpose */
	dump_stack();

	/* Ask to terminate the guest */
	sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}

static void __init early_snp_set_page_state(unsigned long paddr, unsigned int npages, int op)
{
	unsigned long paddr_end, paddr_next;
	u64 old, val;

	paddr = paddr & PAGE_MASK;
	paddr_end = paddr + (npages << PAGE_SHIFT);

	/* save the old GHCB MSR */
	old = sev_es_rd_ghcb_msr();

	for (; paddr < paddr_end; paddr = paddr_next) {

		/*
		 * Use the MSR protocol VMGEXIT to request the page state change. We use the MSR
		 * protocol VMGEXIT because in early boot we may not have the full GHCB setup
		 * yet.
		 */
		sev_es_wr_ghcb_msr(GHCB_SNP_PAGE_STATE_REQ_GFN(paddr >> PAGE_SHIFT, op));
		VMGEXIT();

		val = sev_es_rd_ghcb_msr();

		/* Read the response, if the page state change failed then terminate the guest. */
		if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SNP_PAGE_STATE_CHANGE_RESP)
			sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

		if (GHCB_SNP_PAGE_STATE_RESP_VAL(val) != 0) {
			pr_err("Failed to change page state to '%s' paddr 0x%lx error 0x%llx\n",
					op == SNP_PAGE_STATE_PRIVATE ? "private" : "shared",
					paddr, GHCB_SNP_PAGE_STATE_RESP_VAL(val));

			/* Dump stack for the debugging purpose */
			dump_stack();

			/* Ask to terminate the guest */
			sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
		}

		paddr_next = paddr + PAGE_SIZE;
	}

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(old);
}

void __init early_snp_set_memory_private(unsigned long vaddr, unsigned long paddr,
					 unsigned int npages)
{
	 /* Ask hypervisor to add the memory in RMP table as a 'private'. */
	early_snp_set_page_state(paddr, npages, SNP_PAGE_STATE_PRIVATE);

	/* Validate the memory region after its added in the RMP table. */
	sev_snp_issue_pvalidate(vaddr, npages, true);
}

void __init early_snp_set_memory_shared(unsigned long vaddr, unsigned long paddr,
					unsigned int npages)
{
	/*
	 * We are chaning the memory from private to shared, invalidate the memory region
	 * before making it shared in the RMP table.
	 */
	sev_snp_issue_pvalidate(vaddr, npages, false);

	 /* Ask hypervisor to make the memory shared in the RMP table. */
	early_snp_set_page_state(paddr, npages, SNP_PAGE_STATE_SHARED);
}
