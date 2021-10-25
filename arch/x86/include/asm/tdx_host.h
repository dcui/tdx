/* SPDX-License-Identifier: GPL-2.0 */
/* constants/data definitions for TDX host */

#ifndef __ASM_X86_TDX_HOST_H
#define __ASM_X86_TDX_HOST_H

#ifdef CONFIG_INTEL_TDX_HOST
/*
 * TDX extended return:
 * Some of The "TDX module" SEAMCALLs return extended values (which are function
 * leaf specific) in registers in addition to the completion status code in
 * %rax.  For example, in the error case of TDH.SYS.INIT, the registers hold
 * more detailed information about the error in addition to an error code.  Note
 * that some registers may be unused depending on SEAMCALL functions.
 */
struct tdx_ex_ret {
	union {
		struct {
			u64 rcx;
			u64 rdx;
			u64 r8;
			u64 r9;
			u64 r10;
			u64 r11;
		} regs;
		/*
		 * TDH_SYS_INFO returns the buffer address and its size, and the
		 * CMR_INFO address and its number of entries.
		 */
		struct {
			u64 buffer;
			u64 nr_bytes;
			u64 cmr_info;
			u64 nr_cmr_entries;
		} sys_info;
	};
};

const char *tdx_seamcall_error_name(u64 error_code);
void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
			     const struct tdx_ex_ret *ex_ret);

struct tdsysinfo_struct;
const struct tdsysinfo_struct *tdx_get_sysinfo(void);

int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param);

extern u32 tdx_keyids_start __read_mostly;
extern u32 tdx_nr_keyids __read_mostly;
#else
static inline const char *tdx_seamcall_error_name(u64 error_code)
{
	return "";
}

struct tdx_ex_ret;
static inline void pr_seamcall_ex_ret_info(u64 op, u64 error_code,
					   const struct tdx_ex_ret *ex_ret)
{
}

struct tdsysinfo_struct;
static inline const struct tdsysinfo_struct *tdx_get_sysinfo(void)
{
	return NULL;
}

static inline int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param)
{
	return 0;
}
#endif

#endif /* __ASM_X86_TDX_HOST_H */
