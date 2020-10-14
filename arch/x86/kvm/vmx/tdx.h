/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_TDX_H
#define __KVM_X86_TDX_H

#include <linux/list.h>
#include <linux/kvm_host.h>

#include "tdx_arch.h"
#include "tdx_errno.h"
#include "tdx_ops.h"

#ifdef CONFIG_KVM_INTEL_TDX

struct tdx_td_page {
	unsigned long va;
	hpa_t pa;
	bool added;
};

struct kvm_tdx {
	struct kvm kvm;

	struct tdx_td_page tdr;
	struct tdx_td_page tdcs[TDX1_NR_TDCX_PAGES];
};

struct vcpu_tdx {
	struct kvm_vcpu	vcpu;

	struct tdx_td_page tdvpr;
	struct tdx_td_page tdvpx[TDX1_NR_TDVPX_PAGES];
};

static inline bool is_td(struct kvm *kvm)
{
	return kvm->arch.vm_type == KVM_X86_TDX_VM;
}

static inline bool is_td_vcpu(struct kvm_vcpu *vcpu)
{
	return is_td(vcpu->kvm);
}

static inline bool is_debug_td(struct kvm_vcpu *vcpu)
{
	return !vcpu->kvm->arch.guest_state_protected;
}

static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm)
{
	return container_of(kvm, struct kvm_tdx, kvm);
}

static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_tdx, vcpu);
}

static __always_inline void tdvps_vmcs_check(u32 field, u8 bits)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && (field) & 0x1,
			 "Read/Write to TD VMCS *_HIGH fields not supported");

	BUILD_BUG_ON(bits != 16 && bits != 32 && bits != 64);

	BUILD_BUG_ON_MSG(bits != 64 && __builtin_constant_p(field) &&
			 (((field) & 0x6000) == 0x2000 ||
			  ((field) & 0x6000) == 0x6000),
			 "Invalid TD VMCS access for 64-bit field");
	BUILD_BUG_ON_MSG(bits != 32 && __builtin_constant_p(field) &&
			 ((field) & 0x6000) == 0x4000,
			 "Invalid TD VMCS access for 32-bit field");
	BUILD_BUG_ON_MSG(bits != 16 && __builtin_constant_p(field) &&
			 ((field) & 0x6000) == 0x0000,
			 "Invalid TD VMCS access for 16-bit field");
}

static __always_inline void tdvps_gpr_check(u64 field, u8 bits)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(field) && (field) >= NR_VCPU_REGS,
			 "Invalid TD guest GPR index");
}

static __always_inline void tdvps_apic_check(u64 field, u8 bits) {}
static __always_inline void tdvps_dr_check(u64 field, u8 bits) {}
static __always_inline void tdvps_state_check(u64 field, u8 bits) {}
static __always_inline void tdvps_msr_check(u64 field, u8 bits) {}
static __always_inline void tdvps_management_check(u64 field, u8 bits) {}

#define TDX_BUILD_TDVPS_ACCESSORS(bits, uclass, lclass)			       \
static __always_inline u##bits td_##lclass##_read##bits(struct vcpu_tdx *tdx,  \
							u32 field)	       \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdrdvps(tdx->tdvpr.pa, TDVPS_##uclass(field), &ex_ret);	       \
	if (unlikely(err)) {						       \
		pr_err("TDRDVPS["#uclass".0x%x] failed: 0x%llx\n", field, err);\
		return 0;						       \
	}								       \
	return (u##bits)ex_ret.r8;					       \
}									       \
static __always_inline void td_##lclass##_write##bits(struct vcpu_tdx *tdx,    \
						      u32 field, u##bits val)  \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdwrvps(tdx->tdvpr.pa, TDVPS_##uclass(field), val,	       \
		      GENMASK_ULL(bits - 1, 0), &ex_ret);		       \
	if (unlikely(err))						       \
		pr_err("TDWRVPS["#uclass".0x%x] = 0x%llx failed: 0x%llx\n",    \
		       field, (u64)val, err);				       \
}									       \
static __always_inline void td_##lclass##_setbit##bits(struct vcpu_tdx *tdx,   \
						       u32 field, u64 bit)     \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdwrvps(tdx->tdvpr.pa, TDVPS_##uclass(field), bit, bit, &ex_ret);\
	if (unlikely(err))						       \
		pr_err("TDWRVPS["#uclass".0x%x] |= 0x%llx failed: 0x%llx\n",   \
		       field, bit, err);				       \
}									       \
static __always_inline void td_##lclass##_clearbit##bits(struct vcpu_tdx *tdx, \
						         u32 field, u64 bit)   \
{									       \
	struct tdx_ex_ret ex_ret;					       \
	u64 err;							       \
									       \
	tdvps_##lclass##_check(field, bits);				       \
	err = tdwrvps(tdx->tdvpr.pa, TDVPS_##uclass(field), 0, bit, &ex_ret);  \
	if (unlikely(err))						       \
		pr_err("TDWRVPS["#uclass".0x%x] &= ~0x%llx failed: 0x%llx\n",  \
		       field, bit, err);				       \
}

TDX_BUILD_TDVPS_ACCESSORS(16, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(32, VMCS, vmcs);
TDX_BUILD_TDVPS_ACCESSORS(64, VMCS, vmcs);

TDX_BUILD_TDVPS_ACCESSORS(64, APIC, apic);
TDX_BUILD_TDVPS_ACCESSORS(64, GPR, gpr);
TDX_BUILD_TDVPS_ACCESSORS(64, DR, dr);
TDX_BUILD_TDVPS_ACCESSORS(64, STATE, state);
TDX_BUILD_TDVPS_ACCESSORS(64, MSR, msr);
TDX_BUILD_TDVPS_ACCESSORS(8, MANAGEMENT, management);

#else

struct kvm_tdx;
struct vcpu_tdx;

static inline bool is_td(struct kvm *kvm) { return false; }
static inline bool is_td_vcpu(struct kvm_vcpu *vcpu) { return false; }
static inline bool is_debug_td(struct kvm_vcpu *vcpu) { return false; }
static inline struct kvm_tdx *to_kvm_tdx(struct kvm *kvm) { return NULL; }
static inline struct vcpu_tdx *to_tdx(struct kvm_vcpu *vcpu) { return NULL; }

#endif /* CONFIG_KVM_INTEL_TDX */

#endif /* __KVM_X86_TDX_H */
