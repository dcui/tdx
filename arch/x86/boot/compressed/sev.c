// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

/*
 * misc.h needs to be first because it knows how to include the other kernel
 * headers in the pre-decompression code in a way that does not break
 * compilation.
 */
#include "misc.h"

#include <asm/msr-index.h>
#include <asm/sev-snp.h>
#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <asm/svm.h>
#include <asm/trapnr.h>
#include <asm/trap_pf.h>
#include <asm/msr-index.h>
#include <asm/fpu/xcr.h>
#include <asm/ptrace.h>
#include <asm/svm.h>
#include <asm/sev-snp.h>
#include <asm/e820/types.h>
#include "sev-snp.h"
#include "error.h"

struct ghcb boot_ghcb_page __aligned(PAGE_SIZE);
struct ghcb *boot_ghcb;

/*
 * Copy a version of this function here - insn-eval.c can't be used in
 * pre-decompression code.
 */
static bool insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return true;
	}

	return false;
}

/*
 * Only a dummy for insn_get_seg_base() - Early boot-code is 64bit only and
 * doesn't use segments.
 */
static unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	return 0UL;
}

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

/* Provides sev_es_{wr,rd}_ghcb_msr() */
#include "sev-common.c"

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int ret;

	memcpy(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);

	ret = insn_decode(&ctxt->insn, buffer, MAX_INSN_SIZE, INSN_MODE_64);
	if (ret < 0)
		return ES_DECODE_FAILED;

	return ES_OK;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	memcpy(buf, src, size);

	return ES_OK;
}

#undef __init
#undef __pa
#define __init
#define __pa(x)	((unsigned long)(x))

#define __BOOT_COMPRESSED

/* Basic instruction decoding support needed */
#include "../../lib/inat.c"
#include "../../lib/insn.c"

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

static bool early_setup_sev_es(void)
{
	if (!sev_es_negotiate_protocol())
		sev_es_terminate(GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED);

	if (set_page_decrypted((unsigned long)&boot_ghcb_page))
		return false;

	/* Page is now mapped decrypted, clear it */
	memset(&boot_ghcb_page, 0, sizeof(boot_ghcb_page));

	boot_ghcb = &boot_ghcb_page;

	/* Initialize lookup tables for the instruction decoder */
	inat_init_tables();

	/* SEV-SNP guest requires the GHCB GPA must be registered */
	sev_snp_register_ghcb(__pa(&boot_ghcb_page));

	return true;
}

void sev_es_shutdown_ghcb(void)
{
	if (!boot_ghcb)
		return;

	if (!sev_es_check_cpu_features())
		error("SEV-ES CPU Features missing.");

	/*
	 * GHCB Page must be flushed from the cache and mapped encrypted again.
	 * Otherwise the running kernel will see strange cache effects when
	 * trying to use that page.
	 */
	if (set_page_encrypted((unsigned long)&boot_ghcb_page))
		error("Can't map GHCB page encrypted");

	/*
	 * GHCB page is mapped encrypted again and flushed from the cache.
	 * Mark it non-present now to catch bugs when #VC exceptions trigger
	 * after this point.
	 */
	if (set_page_non_present((unsigned long)&boot_ghcb_page))
		error("Can't unmap GHCB page");
}

bool sev_es_check_ghcb_fault(unsigned long address)
{
	/* Check whether the fault was on the GHCB page */
	return ((address & PAGE_MASK) == (unsigned long)&boot_ghcb_page);
}

void do_boot_stage2_vc(struct pt_regs *regs, unsigned long exit_code)
{
	struct es_em_ctxt ctxt;
	enum es_result result;

	if (!boot_ghcb && !early_setup_sev_es())
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result != ES_OK)
		goto finish;

	switch (exit_code) {
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(boot_ghcb, &ctxt, exit_code);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(boot_ghcb, &ctxt);
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(boot_ghcb, &ctxt);
		break;
	default:
		result = ES_UNSUPPORTED;
		break;
	}

finish:
	if (result == ES_OK)
		vc_finish_insn(&ctxt);
	else if (result != ES_RETRY)
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}

void sev_snp_register_ghcb(unsigned long paddr)
{
	u64 pfn = paddr >> PAGE_SHIFT;
	u64 old, val;

	if (!sev_snp_enabled())
		return;

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


static void extend_e820_on_demand(struct boot_e820_entry *e820_entry,
				  u64 needed_ram_end)
{
	u64 end, paddr;
	if (!e820_entry) {
		return;
	}
	// Validated memory must be aligned by PAGE_SIZE
	end = ALIGN(e820_entry->addr + e820_entry->size, PAGE_SIZE);
	if (needed_ram_end > end && e820_entry->type == E820_TYPE_RAM) {
		for (paddr = end; paddr < needed_ram_end; paddr += PAGE_SIZE) {
			sev_snp_issue_pvalidate_page(paddr, true);
		}
		e820_entry->size = needed_ram_end - e820_entry->addr;
	}
}

/*
 * Explictly pvalidate needed pages for decompressing the kernel.
 * The E820_TYPE_RAM entry includes only validated memory. The kernel
 * expects that the RAM entry's addr is fixed while the entry size is to be
 * extended to cover addresses to the start of next entry.
 * The function increases the RAM entry size to cover all possilble memory
 * addresses until init_size.
 * For example,  init_end = 0x4000000,
 * [RAM: 0x0 - 0x0],                       M[RAM: 0x0 - 0xa0000]
 * [RSVD: 0xa0000 - 0x10000]                [RSVD: 0xa0000 - 0x10000]
 * [ACPI: 0x10000 - 0x20000]      ==>       [ACPI: 0x10000 - 0x20000]
 * [RSVD: 0x800000 - 0x900000]              [RSVD: 0x800000 - 0x900000]
 * [RAM: 0x1000000 - 0x2000000]            M[RAM: 0x1000000 - 0x2001000]
 * [RAM: 0x2001000 - 0x2007000]            M[RAM: 0x2001000 - 0x4000000]

 Other RAM memory after init_end is pvalidated by ms_hyperv_init_platform
 */
__visible void pvalidate_for_startup_64(struct boot_params *boot_params)
{
	struct boot_e820_entry *e820_entry;
	u64 init_end =
		boot_params->hdr.pref_address + boot_params->hdr.init_size;
	u64 needed_end;
	u8 i, nr_entries = boot_params->e820_entries;
	if (!sev_snp_enabled()) {
		return;
	}
	for (i = 0; i < nr_entries; ++i) {
		/* Pvalidate memory holes in e820 RAM entries. */
		e820_entry = &boot_params->e820_table[i];
		if (i < nr_entries - 1) {
			needed_end = boot_params->e820_table[i + 1].addr;
			if (needed_end < e820_entry->addr) {
				error("e820 table is not sorted.");
			}
		} else {
			needed_end = init_end;
		}
		extend_e820_on_demand(e820_entry, needed_end);
	}
}
