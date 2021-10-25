// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Trust Domain Extensions (TDX) memory initialization
 */
#define pr_fmt(fmt) "tdx: " fmt

#include <linux/pgtable.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include "tdmr-common.h"

/* Check whether first range is fully covered by second */
static bool __init is_range_fully_covered(u64 r1_start, u64 r1_end,
		u64 r2_start, u64 r2_end)
{
	return (r1_start >= r2_start && r1_end <= r2_end) ? true : false;
}

/* Check whether physical address range is covered by CMR or not. */
static bool __init phys_range_covered_by_cmrs(struct cmr_info *cmr_array,
		int cmr_num, phys_addr_t start, phys_addr_t end)
{
	int i;

	for (i = 0; i < cmr_num; i++) {
		struct cmr_info *cmr = &cmr_array[i];

		if (is_range_fully_covered((u64)start, (u64)end,
					cmr->base, cmr->base + cmr->size))
			return true;
	}

	return false;
}

/*
 * Sanity check whether all TDX memory blocks are fully covered by CMRs.
 * Only convertible memory can truly be used by TDX.
 */
static int __init sanity_check_cmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num)
{
	struct tdx_memblock *tmb;

	/*
	 * Check CMRs against entire TDX memory, rather than against individual
	 * TDX memory block to allow more flexibility, i.e. to allow adding TDX
	 * memory block before CMR info is available.
	 */
	list_for_each_entry(tmb, &tmem->tmb_list, list)
		if (!phys_range_covered_by_cmrs(cmr_array, cmr_num,
				tmb->start_pfn << PAGE_SHIFT,
				tmb->end_pfn << PAGE_SHIFT))
			break;

	/* Return success if all blocks have passed CMR check */
	if (list_entry_is_head(tmb, &tmem->tmb_list, list))
		return 0;

	/*
	 * TDX cannot be enabled in this case.  Explicitly give a message
	 * so user can know the reason of failure.
	 */
	pr_info("Memory [0x%lx, 0x%lx] not fully covered by CMR\n",
				tmb->start_pfn << PAGE_SHIFT,
				tmb->end_pfn << PAGE_SHIFT);
	return -EFAULT;
}

/**************************** Distributing TDMRs ***************************/

/* TDMRs must be 1gb aligned */
#define TDMR_ALIGNMENT		BIT(30)
#define TDMR_PFN_ALIGNMENT	(TDMR_ALIGNMENT >> PAGE_SHIFT)

#define TDX_MEMBLOCK_TDMR_START(_tmb)	\
	(ALIGN_DOWN((_tmb)->start_pfn, TDMR_PFN_ALIGNMENT) << PAGE_SHIFT)
#define TDX_MEMBLOCK_TDMR_END(_tmb)	\
	(ALIGN((_tmb)->end_pfn, TDMR_PFN_ALIGNMENT) << PAGE_SHIFT)

/*
 * Structure to describe an address range, referred as TDMR range, which meets
 * TDMR's 1G alignment.  It is used to assist constructing TDMRs.  Final TDMRs
 * are generated on basis of TDMR range, meaning one TDMR range can have one or
 * multiple TDMRs, but one TDMR cannot cross two TDMR ranges.
 *
 * @start_1g and @end_1g are 1G aligned.  @first_tmb and @last_tmb are the first
 * and last TDX memory block that the TDMR range covers.  Note both @first_tmb
 * and @last_tmb may only have part of it covered by the TDMR range.
 */
struct tdmr_range {
	struct list_head list;
	phys_addr_t start_1g;
	phys_addr_t end_1g;
	int nid;
	struct tdx_memblock *first_tmb;
	struct tdx_memblock *last_tmb;
};

/*
 * Context of a set of TDMR ranges.  It is generated to cover all TDX memory
 * blocks to assist constructing TDMRs.  It can be discarded after TDMRs are
 * generated.
 */
struct tdmr_range_ctx {
	struct tdx_memory *tmem;
	struct list_head tr_list;
	int tr_num;
};

/*
 * Create a TDMR range which covers the TDX memory block @tmb.  @shrink_start
 * indicates whether to shrink first 1G, i.e. when boundary of @tmb and
 * previous block falls into the middle of 1G area, but a new TDMR range for
 * @tmb is desired.
 */
static struct tdmr_range * __init tdmr_range_create(
		struct tdx_memblock *tmb, bool shrink_start)
{
	struct tdmr_range *tr = kzalloc(sizeof(*tr), GFP_KERNEL);

	if (!tr)
		return NULL;

	INIT_LIST_HEAD(&tr->list);

	tr->start_1g = TDX_MEMBLOCK_TDMR_START(tmb);
	if (shrink_start)
		tr->start_1g += TDMR_ALIGNMENT;
	tr->end_1g = TDX_MEMBLOCK_TDMR_END(tmb);
	tr->nid = tmb->nid;
	tr->first_tmb = tr->last_tmb = tmb;

	return tr;
}

static void __init tdmr_range_free(struct tdmr_range *tr)
{
	/* kfree() is NULL safe */
	kfree(tr);
}

/*
 * Extend existing TDMR range to cover new TDX memory block @tmb.
 * The TDMR range which covers @tmb and the existing TDMR range must
 * not have address hole between them.
 */
static void __init tdmr_range_extend(struct tdmr_range *tr,
		struct tdx_memblock *tmb)
{
	WARN_ON_ONCE(TDX_MEMBLOCK_TDMR_START(tmb) > tr->end_1g);
	WARN_ON_ONCE(tr->nid != tmb->nid);
	tr->end_1g = ALIGN(tmb->end_pfn, TDMR_PFN_ALIGNMENT) << PAGE_SHIFT;
	tr->last_tmb = tmb;
}

/* Initialize the context for constructing TDMRs for given TDX memory. */
static void __init tdmr_range_ctx_init(struct tdmr_range_ctx *tr_ctx,
		struct tdx_memory *tmem)
{
	INIT_LIST_HEAD(&tr_ctx->tr_list);
	tr_ctx->tr_num = 0;
	tr_ctx->tmem = tmem;
}

/* Destroy the context for constructing TDMRs */
static void __init tdmr_range_ctx_destroy(struct tdmr_range_ctx *tr_ctx)
{
	while (!list_empty(&tr_ctx->tr_list)) {
		struct tdmr_range *tr = list_first_entry(&tr_ctx->tr_list,
				struct tdmr_range, list);

		list_del(&tr->list);
		tdmr_range_free(tr);
	}
	tr_ctx->tr_num = 0;
	tr_ctx->tmem = NULL;
}

/*
 * Generate a list of TDMR ranges for given TDX memory @tmem, as a preparation
 * to construct final TDMRs.
 */
static int __init generate_tdmr_ranges(struct tdmr_range_ctx *tr_ctx)
{
	struct tdx_memory *tmem = tr_ctx->tmem;
	struct tdx_memblock *tmb;
	struct tdmr_range *last_tr = NULL;

	list_for_each_entry(tmb, &tmem->tmb_list, list) {
		struct tdmr_range *tr;

		/* Create a new TDMR range for the first @tmb */
		if (!last_tr) {
			tr = tdmr_range_create(tmb, false);
			if (!tr)
				return -ENOMEM;
			/* Add to tail to keep TDMR ranges in ascending order */
			list_add_tail(&tr->list, &tr_ctx->tr_list);
			tr_ctx->tr_num++;
			last_tr = tr;
			continue;
		}

		/*
		 * Always create a new TDMR range if @tmb belongs to a new NUMA
		 * node, to ensure the TDMR and the PAMT which covers it are on
		 * the same NUMA node.
		 */
		if (tmb->nid != last_tr->last_tmb->nid) {
			/*
			 * If boundary of two NUMA nodes falls into the middle
			 * of 1G area, then part of @tmb has already been
			 * covered by first node's last TDMR range.  In this
			 * case, shrink the new TDMR range.
			 */
			bool shrink_start = TDX_MEMBLOCK_TDMR_START(tmb) <
				last_tr->end_1g ? true : false;

			tr = tdmr_range_create(tmb, shrink_start);
			if (!tr)
				return -ENOMEM;
			list_add_tail(&tr->list, &tr_ctx->tr_list);
			tr_ctx->tr_num++;
			last_tr = tr;
			continue;
		}

		/*
		 * Always extend existing TDMR range to cover new @tmb if part
		 * of @tmb has already been covered, regardless memory type of
		 * @tmb.
		 */
		if (TDX_MEMBLOCK_TDMR_START(tmb) < last_tr->end_1g) {
			tdmr_range_extend(last_tr, tmb);
			continue;
		}

		/*
		 * By reaching here, the new @tmb is in the same NUMA node, and
		 * is not covered by last TDMR range.  Always create a new TDMR
		 * range in this case, so that final TDMRs won't cross TDX
		 * memory block boundary.
		 */
		tr = tdmr_range_create(tmb, false);
		if (!tr)
			return -ENOMEM;
		list_add_tail(&tr->list, &tr_ctx->tr_list);
		tr_ctx->tr_num++;
		last_tr = tr;
	}

	return 0;
}

/******************************* External APIs *****************************/

/**
 * tdx_memblock_create:	Create one TDX memory block
 *
 * @start_pfn:	Start PFN of the TDX memory block
 * @end_pfn:	End PFN of the TDX memory block
 * @nid:	Node the TDX memory block belongs to
 * @data:	Type-specific TDX memory block opaque data
 * @ops:	Type-specific TDX memory block ops
 *
 * Create one TDX memory block with type-specific data and ops.
 */
struct tdx_memblock * __init tdx_memblock_create(unsigned long start_pfn,
		unsigned long end_pfn, int nid, void *data,
		struct tdx_memblock_ops *ops)
{
	struct tdx_memblock *tmb;

	tmb = kzalloc(sizeof(*tmb), GFP_KERNEL);
	if (!tmb)
		return NULL;

	INIT_LIST_HEAD(&tmb->list);
	tmb->start_pfn = start_pfn;
	tmb->end_pfn = end_pfn;
	tmb->data = data;
	tmb->ops = ops;

	return tmb;
}

/**
 * tdx_memblock_free:	Free the TDX memory block
 *
 * @tmb:	TDX memory block to free
 */
void __init tdx_memblock_free(struct tdx_memblock *tmb)
{
	if (!tmb)
		return;

	tmb->ops->tmb_free(tmb);
	kfree(tmb);
}

/**
 * tdx_memory_init:	Initialize one TDX memory instance
 *
 * @tmem:	The TDX memory to initialize.
 */
void __init tdx_memory_init(struct tdx_memory *tmem)
{
	INIT_LIST_HEAD(&tmem->tmb_list);
}

/**
 * tdx_memory_destroy:	Destroy one TDX memory instance
 *
 * @tmem:	The TDX memory to destroy
 */
void __init tdx_memory_destroy(struct tdx_memory *tmem)
{
	while (!list_empty(&tmem->tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(&tmem->tmb_list,
				struct tdx_memblock, list);

		list_del(&tmb->list);
		tdx_memblock_free(tmb);
	}
}

/**
 * tdx_memory_add_block:	Add a TDX memory block to TDX memory instance
 *
 * @tmem:	The TDX memory instance to add to
 * @tmb:	The TDX memory block to add
 *
 * Add a TDX memory block to TDX memory instance in address ascending order.
 *
 * Returns 0 on success, or failure if the new block overlaps with any existing
 * ones in TDX memory.
 */
int __init tdx_memory_add_block(struct tdx_memory *tmem,
		struct tdx_memblock *tmb)
{
	struct tdx_memblock *p;

	/* Insert new @tmb to @tr in address ascending order */
	list_for_each_entry_reverse(p, &tmem->tmb_list, list) {
		if (p->start_pfn >= tmb->end_pfn)
			continue;
		/*
		 * Found memory block at lower position.  Sanity check the new
		 * block doesn't overlap with the existing one.
		 */
		if (WARN_ON_ONCE(p->end_pfn > tmb->start_pfn))
			return -EFAULT;

		break;
	}

	/*
	 * @p is either head, or valid memory block which is at lower
	 * position than @tmb.
	 */
	list_add(&tmb->list, &p->list);

	return 0;
}

/**
 * tdx_memory_merge:	Merge two TDX memory instances to one
 *
 * @tmem_dst:	The first TDX memory as destination
 * @tmem_src:	The second TDX memory as source
 *
 * Merge all TDX memory blocks in @tmem_src to @tmem_dst.  This allows caller
 * to build multiple intermediate TDX memory instances based on TDX memory type
 * (for instance, system memory, or x86 legacy PMEM) and/or NUMA locality, and
 * merge them together as final TDX memory to generate final TDMRs.
 *
 * On success, @tmem_src will be empty.  In case of any error, some TDX memory
 * blocks in @tmem_src may have already been moved to @tmem_dst.  Caller is
 * responsible for destroying both @tmem_src and @tmem_dst.
 */
int __init tdx_memory_merge(struct tdx_memory *tmem_dst,
		struct tdx_memory *tmem_src)
{
	while (!list_empty(&tmem_src->tmb_list)) {
		struct tdx_memblock *tmb = list_first_entry(&tmem_src->tmb_list,
				struct tdx_memblock, list);
		int ret;

		list_del(&tmb->list);

		ret = tdx_memory_add_block(tmem_dst, tmb);
		if (ret) {
			/*
			 * Add @tmb back to @tmem_src, so it can be properly
			 * freed by caller.
			 */
			list_add(&tmb->list, &tmem_src->tmb_list);
			return ret;
		}
	}

	return 0;
}

/**
 * tdx_memory_construct_tdmrs:	Construct final TDMRs to cover all TDX memory
 *				blocks in final TDX memory
 *
 * @tmem:		The final TDX memory
 * @cmr_array:		Array of CMR entries
 * @cmr_num:		Number of CMR entries
 * @desc:		TDX module descriptor for constructing final TMDRs
 * @tdmr_info_array:	Array of constructed final TDMRs
 * @tdmr_num:		Number of final TDMRs
 *
 * Construct final TDMRs to cover all TDX memory blocks in final TDX memory,
 * based on CMR info and TDX module descriptor.  Caller is responsible for
 * allocating enough space for array of final TDMRs @tdmr_info_array (i.e. by
 * allocating enough space based on @desc.max_tdmr_num).
 *
 * Upon success, all final TDMRs will be stored in @tdmr_info_array, and
 * @tdmr_num will have the actual number of TDMRs.  On failure, @tmem internal
 * state is cleared, and caller is responsible for destroying it.
 */
int __init tdx_memory_construct_tdmrs(struct tdx_memory *tmem,
		struct cmr_info *cmr_array, int cmr_num,
		struct tdx_module_descriptor *desc,
		struct tdmr_info *tdmr_info_array, int *tdmr_num)
{
	struct tdmr_range_ctx tr_ctx;
	int ret;

	BUILD_BUG_ON(sizeof(struct tdmr_info) != 512);

	/*
	 * Sanity check TDX module descriptor.  TDX module should have the
	 * architectural values in TDX spec.
	 */
	if (WARN_ON_ONCE((desc->max_tdmr_num != TDX_MAX_NR_TDMRS) ||
		(desc->max_tdmr_rsvd_area_num != TDX_MAX_NR_RSVD_AREAS) ||
		(desc->pamt_entry_size[TDX_PG_4K] != TDX_PAMT_ENTRY_SIZE) ||
		(desc->pamt_entry_size[TDX_PG_2M] != TDX_PAMT_ENTRY_SIZE) ||
		(desc->pamt_entry_size[TDX_PG_1G] != TDX_PAMT_ENTRY_SIZE)))
		return -EINVAL;

	/*
	 * Sanity check number of CMR entries.  It should not exceed maximum
	 * value defined by TDX spec.
	 */
	if (WARN_ON_ONCE((cmr_num > TDX_MAX_NR_CMRS) || (cmr_num <= 0)))
		return -EINVAL;

	ret = sanity_check_cmrs(tmem, cmr_array, cmr_num);
	if (ret)
		return ret;

	/* Generate a list of TDMR ranges to cover all TDX memory blocks */
	tdmr_range_ctx_init(&tr_ctx, tmem);
	ret = generate_tdmr_ranges(&tr_ctx);
	if (ret)
		goto tr_ctx_err;

	return 0;
tr_ctx_err:
	tdmr_range_ctx_destroy(&tr_ctx);
	return ret;
}
