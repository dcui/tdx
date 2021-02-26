// SPDX-License-Identifier: GPL-2.0
/*
 * AMD SEV SNP support
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 */

#include "misc.h"
#include "error.h"

#include <asm/msr-index.h>
#include <asm/sev-snp.h>
#include <asm/sev.h>
#include <asm/svm.h>
#include <asm/trapnr.h>
#include <asm/fpu/xcr.h>

#include "sev-snp.h"

static bool sev_snp_enabled(void)
{
	unsigned long low, high;
	u64 val;

	asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV));

	val = (high << 32) | low;

	if (val & MSR_AMD64_SEV_SNP_ENABLED)
		return true;

	return false;
}

/* Provides sev_snp_{wr,rd}_ghcb_msr() */
#include "sev-common.c"

/* Include code for early handlers */
#include "../../kernel/sev-shared.c"

static void sev_snp_pages_state_change(unsigned long paddr, int op)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 old, val;

	/* save the old GHCB MSR */
	old = sev_es_rd_ghcb_msr();

	/* Issue VMGEXIT to change the page state */
	sev_es_wr_ghcb_msr(GHCB_SNP_PAGE_STATE_REQ_GFN(pfn, op));
	VMGEXIT();

	/* Read the response of the VMGEXIT */
	val = sev_es_rd_ghcb_msr();
	if ((GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SNP_PAGE_STATE_CHANGE_RESP) ||
	    (GHCB_SNP_PAGE_STATE_RESP_VAL(val) != 0))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(old);
}

static void sev_snp_issue_pvalidate(unsigned long paddr, bool validate)
{
	unsigned long eflags;
	int rc;

	rc = __pvalidate(paddr, RMP_PG_SIZE_4K, validate, &eflags);
	if (rc) {
		error("Failed to validate address");
		goto e_fail;
	}

	/* Check for the double validation and assert on failure */
	if (eflags & X86_EFLAGS_CF) {
		error("Double validation detected");
		goto e_fail;
	}

	return;
e_fail:
	sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}

static void sev_snp_set_page_private_shared(unsigned long paddr, int op)
{
	if (!sev_snp_enabled())
		return;

	/*
	 * We are change the page state from private to shared, invalidate the pages before
	 * making the page state change in the RMP table.
	 */
	if (op == SNP_PAGE_STATE_SHARED)
		sev_snp_issue_pvalidate(paddr, false);

	/* Request the page state change in the RMP table. */
	sev_snp_pages_state_change(paddr, op);

	/*
	 * Now that pages are added in the RMP table as a private memory, validate the
	 * memory range so that it is consistent with the RMP entry.
	 */
	if (op == SNP_PAGE_STATE_PRIVATE)
		sev_snp_issue_pvalidate(paddr, true);
}

void sev_snp_set_page_private(unsigned long paddr)
{
	sev_snp_set_page_private_shared(paddr, SNP_PAGE_STATE_PRIVATE);
}

void sev_snp_set_page_shared(unsigned long paddr)
{
	sev_snp_set_page_private_shared(paddr, SNP_PAGE_STATE_SHARED);
}
