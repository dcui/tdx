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
	return hv_get_isolation_type() != HV_ISOLATION_TYPE_NONE;
}
EXPORT_SYMBOL_GPL(hv_is_isolation_supported);

bool hv_isolation_type_snp(void)
{
	return hv_get_isolation_type() == HV_ISOLATION_TYPE_SNP;
}
EXPORT_SYMBOL_GPL(hv_isolation_type_snp);

int hv_mark_gpa_visibility(u16 count, const u64 pfn[], u32 visibility)
{
	struct hv_input_modify_sparse_gpa_page_host_visibility **input_pcpu;
	struct hv_input_modify_sparse_gpa_page_host_visibility *input;
	u16 pages_processed;
	u64 hv_status;
	unsigned long flags;

	/* no-op if partition isolation is not enabled */
	if (!hv_is_isolation_supported())
		return 0;

	if (count > HV_MAX_MODIFY_GPA_REP_COUNT) {
		pr_err("Hyper-V: GPA count:%d exceeds supported:%lu\n", count,
			HV_MAX_MODIFY_GPA_REP_COUNT);
		return -EINVAL;
	}

	local_irq_save(flags);
	input_pcpu = (struct hv_input_modify_sparse_gpa_page_host_visibility **)
			this_cpu_ptr(hyperv_pcpu_input_arg);
	input = *input_pcpu;
	if (unlikely(!input)) {
		local_irq_restore(flags);
		return -1;
	}

	input->partition_id = HV_PARTITION_ID_SELF;
	input->host_visibility = visibility;
	input->reserved0 = 0;
	input->reserved1 = 0;
	memcpy((void *)input->gpa_page_list, pfn, count * sizeof(*pfn));
	do {
		hv_status = hv_do_rep_hypercall(
				HVCALL_MODIFY_SPARSE_GPA_PAGE_HOST_VISIBILITY, count,
				0, input, &pages_processed);
	} while (hv_status == 0x78);
	local_irq_restore(flags);

	if (!(hv_status & HV_HYPERCALL_RESULT_MASK))
		return 0;

	printk("%s:%d (%s): hv_status=%llx\n", __FILE__, __LINE__, __func__, hv_status);
	return -EFAULT;
}
EXPORT_SYMBOL(hv_mark_gpa_visibility);
