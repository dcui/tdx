/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_GENERIC_MS_HYPERV_INFO_H
#define _ASM_GENERIC_MS_HYPERV_INFO_H

struct ms_hyperv_info {
	u32 features;
	u32 priv_high;
	u32 misc_features;
	u32 hints;
	u32 nested_features;
	u32 max_vp_index;
	u32 max_lp_index;
	u32 isolation_config_a;
	union {
		u32 isolation_config_b;
		struct {
			u32 cvm_type : 4;
			u32 reserved1 : 1;
			u32 shared_gpa_boundary_active : 1;
			u32 shared_gpa_boundary_bits : 6;
			u32 reserved2 : 20;
		};
	};
	u64 shared_gpa_boundary;
};
extern struct ms_hyperv_info ms_hyperv;

#endif
