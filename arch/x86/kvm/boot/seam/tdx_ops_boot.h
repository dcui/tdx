/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BOOT_TDX_OPS_H
#define __BOOT_TDX_OPS_H

#ifdef CONFIG_KVM_INTEL_TDX

static inline u64 tdh_sys_key_config(void)
{
	return seamcall_boot(TDH_SYS_KEY_CONFIG, 0, 0, 0, 0, NULL);
}

static inline u64 tdh_sys_info(u64 tdsysinfo, int nr_bytes, u64 cmr_info,
			       int nr_cmr_entries, struct tdx_ex_ret *ex)
{
	return seamcall_boot(TDH_SYS_INFO, tdsysinfo, nr_bytes, cmr_info,
			     nr_cmr_entries, ex);
}

static inline u64 tdh_sys_init(u64 attributes, struct tdx_ex_ret *ex)
{
	return seamcall_boot(TDH_SYS_INIT, attributes, 0, 0, 0, ex);
}

static inline u64 tdh_sys_lp_init(struct tdx_ex_ret *ex)
{
	return seamcall_boot(TDH_SYS_LP_INIT, 0, 0, 0, 0, ex);
}

static inline u64 tdh_sys_tdmr_init(u64 tdmr, struct tdx_ex_ret *ex)
{
	return seamcall_boot(TDH_SYS_TDMR_INIT, tdmr, 0, 0, 0, ex);
}

static inline u64 tdh_sys_config(u64 tdmr, int nr_entries, int hkid)
{
	return seamcall_boot(TDH_SYS_CONFIG, tdmr, nr_entries, hkid, 0, NULL);
}

#endif

#endif /* __BOOT_TDX_OPS_H */
