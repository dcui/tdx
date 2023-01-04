// SPDX-License-Identifier: GPL-2.0
/*
 * Hyper-V Isolation VM interface with paravisor and hypervisor
 *
 * Author:
 *  Tianyu Lan <Tianyu.Lan@microsoft.com>
 */
#include <linux/types.h>
#include <linux/bitfield.h>
#include <asm/io.h>
#include <asm/sev.h>
#include <asm/svm.h>
#include <asm/mshyperv.h>

enum hv_isolation_type hv_get_isolation_type(void)
{
	if (!(ms_hyperv.isolation_config_b & HV_ISOLATION))
		return HV_ISOLATION_TYPE_NONE;
	return FIELD_GET(HV_ISOLATION_TYPE, ms_hyperv.isolation_config_b);
}
EXPORT_SYMBOL_GPL(hv_get_isolation_type);

bool hv_is_isolation_supported(void)
{
	return true;
//	return hv_get_isolation_type() != HV_ISOLATION_TYPE_NONE;
}
EXPORT_SYMBOL_GPL(hv_is_isolation_supported);

bool hv_isolation_type_snp(void)
{
	return true;
	//return hv_get_isolation_type() == HV_ISOLATION_TYPE_SNP;
}
EXPORT_SYMBOL_GPL(hv_isolation_type_snp);
