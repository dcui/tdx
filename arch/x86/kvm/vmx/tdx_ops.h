/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX SEAMCALLs */

#ifndef __KVM_X86_TDX_OPS_H
#define __KVM_X86_TDX_OPS_H

#include <linux/compiler.h>

#include <asm/asm.h>
#include <asm/kvm_host.h>

#include "tdx_errno.h"
#include "tdx_arch.h"
#include "seamcall.h"

#ifdef CONFIG_INTEL_TDX_HOST

static inline u64 tdh_mng_addcx(hpa_t tdr, hpa_t addr)
{
	return seamcall(TDH_MNG_ADDCX, addr, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_page_add(hpa_t tdr, gpa_t gpa, hpa_t hpa, hpa_t source,
			    union tdx_ex_ret *ex)
{
	return seamcall(TDH_MEM_PAGE_ADD, gpa, tdr, hpa, source, 0, ex);
}

static inline u64 tdh_mem_sept_add(hpa_t tdr, gpa_t gpa, int level, hpa_t page,
			    union tdx_ex_ret *ex)
{
	return seamcall(TDH_MEM_SEPT_ADD, gpa | level, tdr, page, 0, 0, ex);
}

static inline u64 tdh_vp_addcx(hpa_t tdvpr, hpa_t addr)
{
	return seamcall(TDH_VP_ADDCX, addr, tdvpr, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_page_aug(hpa_t tdr, gpa_t gpa, hpa_t hpa,
			    union tdx_ex_ret *ex)
{
	return seamcall(TDH_MEM_PAGE_AUG, gpa, tdr, hpa, 0, 0, ex);
}

static inline u64 tdh_mem_range_block(hpa_t tdr, gpa_t gpa, int level,
			  union tdx_ex_ret *ex)
{
	return seamcall(TDH_MEM_RANGE_BLOCK, gpa | level, tdr, 0, 0, 0, ex);
}

static inline u64 tdh_mng_key_config(hpa_t tdr)
{
	return seamcall(TDH_MNG_KEY_CONFIG, tdr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_create(hpa_t tdr, int hkid)
{
	return seamcall(TDH_MNG_CREATE, tdr, hkid, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_create(hpa_t tdr, hpa_t tdvpr)
{
	return seamcall(TDH_VP_CREATE, tdvpr, tdr, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_rd(hpa_t tdr, u64 field, union tdx_ex_ret *ex)
{
	return seamcall(TDH_MNG_RD, tdr, field, 0, 0, 0, ex);
}

static inline u64 tdh_mr_extend(hpa_t tdr, gpa_t gpa, union tdx_ex_ret *ex)
{
	return seamcall(TDH_MR_EXTEND, gpa, tdr, 0, 0, 0, ex);
}

static inline u64 tdh_mr_finalize(hpa_t tdr)
{
	return seamcall(TDH_MR_FINALIZE, tdr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_flush(hpa_t tdvpr)
{
	return seamcall(TDH_VP_FLUSH, tdvpr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_vpflushdone(hpa_t tdr)
{
	return seamcall(TDH_MNG_VPFLUSHDONE, tdr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_key_freeid(hpa_t tdr)
{
	return seamcall(TDH_MNG_KEY_FREEID, tdr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mng_init(hpa_t tdr, hpa_t td_params, union tdx_ex_ret *ex)
{
	return seamcall(TDH_MNG_INIT, tdr, td_params, 0, 0, 0, ex);
}

static inline u64 tdh_vp_init(hpa_t tdvpr, u64 rcx)
{
	return seamcall(TDH_VP_INIT, tdvpr, rcx, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_rd(hpa_t tdvpr, u64 field, union tdx_ex_ret *ex)
{
	return seamcall(TDH_VP_RD, tdvpr, field, 0, 0, 0, ex);
}

static inline u64 tdh_mng_key_reclaimid(hpa_t tdr)
{
	return seamcall(TDH_MNG_KEY_RECLAIMID, tdr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_phymem_page_reclaim(hpa_t page, union tdx_ex_ret *ex)
{
	return seamcall(TDH_PHYMEM_PAGE_RECLAIM, page, 0, 0, 0, 0, ex);
}

static inline u64 tdh_mem_page_remove(hpa_t tdr, gpa_t gpa, int level,
				union tdx_ex_ret *ex)
{
	return seamcall(TDH_MEM_PAGE_REMOVE, gpa | level, tdr, 0, 0, 0, ex);
}

static inline u64 tdh_sys_lp_shutdown(void)
{
	return seamcall(TDH_SYS_LP_SHUTDOWN, 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_track(hpa_t tdr)
{
	return seamcall(TDH_MEM_TRACK, tdr, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_mem_range_unblock(hpa_t tdr, gpa_t gpa, int level,
			    union tdx_ex_ret *ex)
{
	return seamcall(TDH_MEM_RANGE_UNBLOCK, gpa | level, tdr, 0, 0, 0, ex);
}

static inline u64 tdh_phymem_cache_wb(bool resume)
{
	return seamcall(TDH_PHYMEM_CACHE_WB, resume ? 1 : 0, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_phymem_page_wbinvd(hpa_t page)
{
	return seamcall(TDH_PHYMEM_PAGE_WBINVD, page, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_vp_wr(hpa_t tdvpr, u64 field, u64 val, u64 mask,
			  union tdx_ex_ret *ex)
{
	return seamcall(TDH_VP_WR, tdvpr, field, val, mask, 0, ex);
}
#endif /* CONFIG_INTEL_TDX_HOST */

#endif /* __KVM_X86_TDX_OPS_H */
