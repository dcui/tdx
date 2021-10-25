// SPDX-License-Identifier: GPL-2.0
/* functions to record TDX SEAMCALL error */

#include <linux/trace_events.h>

#include <asm/tdx_errno.h>
#include <asm/tdx_arch.h>
#include <asm/tdx_host.h>

#include "p-seamldr.h"

#define CREATE_TRACE_POINTS
#include <asm/trace/seam.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_enter);
EXPORT_TRACEPOINT_SYMBOL_GPL(seamcall_exit);

struct tdx_seamcall_status {
	u64 err_code;
	const char *err_name;
};

static const struct tdx_seamcall_status p_seamldr_error_codes[] = {
	P_SEAMLDR_ERROR_CODES
};

const char *p_seamldr_error_name(u64 error_code)
{
	struct tdx_seamcall_status status;
	int i;

	for (i = 0; i < ARRAY_SIZE(p_seamldr_error_codes); i++) {
		status = p_seamldr_error_codes[i];
		if (error_code == status.err_code)
			return status.err_name;
	}
	return "Unknown SEAMLDR error code";
}

static const struct tdx_seamcall_status tdx_status_codes[] = {
	TDX_STATUS_CODES
};

const char *tdx_seamcall_error_name(u64 error_code)
{
	struct tdx_seamcall_status status;
	int i;

	for (i = 0; i < ARRAY_SIZE(tdx_status_codes); i++) {
		status = tdx_status_codes[i];
		if ((error_code & TDX_SEAMCALL_STATUS_MASK) == status.err_code)
			return status.err_name;
	}

	return "Unknown SEAMCALL status code";
}
EXPORT_SYMBOL_GPL(tdx_seamcall_error_name);

static const char * const TDX_SEPT_ENTRY_STATES[] = {
	"SEPT_FREE",
	"SEPT_BLOCKED",
	"SEPT_PENDING",
	"SEPT_PENDING_BLOCKED",
	"SEPT_PRESENT"
};

void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			     const struct tdx_ex_ret *ex_ret)
{
	if (WARN_ON(!ex_ret))
		return;

	switch (error_code & TDX_SEAMCALL_STATUS_MASK) {
	case TDX_INCORRECT_CPUID_VALUE:
		pr_err("Expected CPUID [leaf 0x%x subleaf 0x%x]: "
			"eax 0x%x check_mask 0x%x, ebx 0x%x check_mask 0x%x, "
			"ecx 0x%x check_mask 0x%x, edx 0x%x check_mask 0x%x\n",
			ex_ret->sys_init.leaf, ex_ret->sys_init.subleaf,
			ex_ret->sys_init.eax_val, ex_ret->sys_init.eax_mask,
			ex_ret->sys_init.ebx_val, ex_ret->sys_init.ebx_mask,
			ex_ret->sys_init.ecx_val, ex_ret->sys_init.ecx_mask,
			ex_ret->sys_init.edx_val, ex_ret->sys_init.edx_mask);
		break;
	case TDX_INCONSISTENT_CPUID_FIELD:
		pr_err("Inconsistent CPUID [leaf 0x%x subleaf 0x%x]: "
			"eax_mask 0x%x, ebx_mask 0x%x, ecx_mask %x, edx_mask 0x%x\n",
			ex_ret->sys_init.leaf, ex_ret->sys_init.subleaf,
			ex_ret->sys_init.eax_mask, ex_ret->sys_init.ebx_mask,
			ex_ret->sys_init.ecx_mask, ex_ret->sys_init.edx_mask);
		break;
	case TDX_EPT_WALK_FAILED: {
		const char *state;

		if (ex_ret->sept_walk.state >= ARRAY_SIZE(TDX_SEPT_ENTRY_STATES))
			state = "Invalid";
		else
			state = TDX_SEPT_ENTRY_STATES[ex_ret->sept_walk.state];

		pr_err("Secure EPT walk error: SEPTE 0x%llx, level %d, %s\n",
			ex_ret->sept_walk.septe, ex_ret->sept_walk.level, state);
		break;
	}
	default:
		/* TODO: print only meaningful registers depending on op */
		pr_err("RCX 0x%llx, RDX 0x%llx, R8 0x%llx, R9 0x%llx, "
		       "R10 0x%llx, R11 0x%llx\n",
			ex_ret->regs.rcx, ex_ret->regs.rdx, ex_ret->regs.r8,
			ex_ret->regs.r9, ex_ret->regs.r10, ex_ret->regs.r11);
		break;
	}
}
EXPORT_SYMBOL_GPL(pr_seamcall_ex_ret_info);
