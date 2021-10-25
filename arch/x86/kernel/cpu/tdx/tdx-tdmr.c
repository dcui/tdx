// SPDX-License-Identifier: GPL-2.0
/*
 * Convert all types of TDX capable memory to final TDX memory.
 */

#define pr_fmt(fmt) "tdx: " fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/cache.h>
#include <asm/page_types.h>
#include <asm/tdx_host.h>
#include <asm/page_types.h>
#include "tdx-tdmr.h"

/*
 * Final TDX memory which contains all memory blocks that can be used by TDX.
 * Use this to construct final TDMRs.
 */
struct tdx_memory tmem_all;

/*
 * Merge subtype TDX memory to final TDX memory.
 */
static int __init merge_subtype_tdx_memory(struct tdx_memory *final_tmem,
		struct tdx_memory *subtype_tmem, char *subtype_name)
{
	int ret;

	ret = tdx_memory_merge(final_tmem, subtype_tmem);
	if (ret)
		pr_err("Fail to merge %s as TDX memory\n", subtype_name);

	return ret;
}

/**
 * build_final_tdx_memory:	Build final TDX memory which contains all TDX
 *				capable memory blocks.
 *
 * Build final TDX memory which contains all TDX capable memory blocks by
 * merging all sub-types of TDX capable memory that have been built.  After
 * this function, all TDX capable memory blocks will be in @tmem_all.  In case
 * of any error, all TDX memory intances are destroyed internally.
 */
int __init build_final_tdx_memory(void)
{
	int ret;

	tdx_memory_init(&tmem_all);

	ret = merge_subtype_tdx_memory(&tmem_all, &tmem_sysmem,
			"system memory");
	if (ret)
		goto err;

#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
	ret = merge_subtype_tdx_memory(&tmem_all, &tmem_legacy_pmem,
			"legacy PMEM");
#endif
	if (ret)
		goto err;

	return 0;
err:
	tdx_memory_destroy(&tmem_all);
	cleanup_subtype_tdx_memory();
	return ret;
}

/**
 * cleanup_subtype_tdx_memory:	Clean up all subtypes TDX memory
 *
 * Clean up all subtypes TDX memory as resource cleanup in case of any error
 * before build_final_tdx_memory().
 */
void __init cleanup_subtype_tdx_memory(void)
{
	tdx_sysmem_cleanup();
#ifdef CONFIG_ENABLE_TDX_FOR_X86_PMEM_LEGACY
	tdx_legacy_pmem_cleanup();
#endif
}

/**
 * construct_tdx_tdmrs:	Construct final TDMRs to cover all TDX memory
 *
 * @cmr_array:		Arrry of CMR entries
 * @cmr_num:		Number of CMR entries
 * @desc:		TDX module descriptor for constructing final TMDRs
 * @tdmr_info_array:	Array of final TDMRs
 * @tdmr_num:		Number of final TDMRs
 *
 * Construct final TDMRs to cover all TDX memory blocks in @tmem_all.
 * Caller needs to allocate enough storage for @tdmr_info_array, i.e. by
 * allocating enough entries indicated by desc->max_tdmr_num.
 *
 * Upon success, all TDMRs are stored in @tdmr_info_array, with @tdmr_num
 * indicting the actual TDMR number.
 */
int __init construct_tdx_tdmrs(struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_info_array, int *tdmr_num)
{
	int ret = 0;
	int i;
	struct tdx_memblock *tmb;

	/* No TDX memory available */
	if (list_empty(&tmem_all.tmb_list))
		return -EFAULT;

	ret = tdx_memory_construct_tdmrs(&tmem_all, cmr_array, cmr_num,
			desc, tdmr_info_array, tdmr_num);
	if (ret) {
		pr_err("Failed to construct TDMRs\n");
		goto out;
	}

	i = 0;
	list_for_each_entry(tmb, &tmem_all.tmb_list, list) {
		pr_info("TDX TDMR[%2d]: base 0x%016lx size 0x%016lx\n",
			i, tmb->start_pfn << PAGE_SHIFT,
			tmb->end_pfn << PAGE_SHIFT);
		if (tmb->pamt)
			pr_info("TDX PAMT[%2d]: base 0x%016lx size 0x%016lx\n",
				i, tmb->pamt->pamt_pfn << PAGE_SHIFT,
				tmb->pamt->total_pages << PAGE_SHIFT);
		i++;
	}

out:
	/*
	 * Keep @tmem_all if constructing TDMRs was successfully done, since
	 * memory hotplug needs it to check whether new memory can be added
	 * or not.
	 */
	if (ret)
		tdx_memory_destroy(&tmem_all);
	return ret;
}

/**
 * range_is_tdx_memory:		Check whether range is TDX memory
 *
 * @start:	Range start physical address
 * @end:	Range end physical address
 *
 * Check whether given range is TDX memory.  This allows memory hotplug to
 * fail when TDX is enabled, because TDX doesn't support memory hotplug.
 *
 * This function should be called after TDX module is properly initialized.
 */
bool range_is_tdx_memory(phys_addr_t start, phys_addr_t end)
{
	struct tdx_memblock *tmb;

	/*
	 * @tmem_all being empty means TDX is not enabled.  Return true
	 * in this case to not impact normal memory hotplug behaviour.
	 */
	if (list_empty(&tmem_all.tmb_list))
		return true;

	/*
	 * Target range is TDX memory if it is fully covered by one TDX
	 * memory block in @tmem_all.
	 */
	list_for_each_entry(tmb, &tmem_all.tmb_list, list) {
		phys_addr_t tmb_start, tmb_end;

		tmb_start = tmb->start_pfn << PAGE_SHIFT;
		tmb_end = tmb->end_pfn << PAGE_SHIFT;
		if (tmb_start <= start && tmb_end >= end)
			return true;
	}

	return false;
}
