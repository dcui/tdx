/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_KVM_BOOT_H
#define _ASM_X86_KVM_BOOT_H

#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <asm/processor.h>

#ifdef CONFIG_KVM_INTEL_TDX

/*
 * Return pointer to TDX system info (TDSYSINFO_STRUCT) if TDX has been
 * successfully initialized, or NULL.
 */
struct tdsysinfo_struct;
const struct tdsysinfo_struct *tdx_get_sysinfo(void);

extern u32 tdx_seam_keyid __ro_after_init;

int tdx_seamcall_on_each_pkg(int (*fn)(void *), void *param);

/* TDX keyID allocation functions */
extern int tdx_keyid_alloc(void);
extern void tdx_keyid_free(int keyid);

#endif

#endif /* _ASM_X86_KVM_BOOT_H */
