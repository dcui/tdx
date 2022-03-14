// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021-2022 Intel Corporation */

#undef pr_fmt
#define pr_fmt(fmt)     "tdx: " fmt

#include <linux/cpufeature.h>
#include <asm/coco.h>
#include <asm/tdx.h>
#include <asm/vmx.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>

/* TDX module Call Leaf IDs */
#define TDX_GET_INFO			1
#define TDX_GET_VEINFO			3

/* MMIO direction */
#define EPT_READ	0
#define EPT_WRITE	1

/* See Exit Qualification for I/O Instructions in VMX documentation */
#define VE_IS_IO_IN(e)		((e) & BIT(3))
#define VE_GET_IO_SIZE(e)	(((e) & GENMASK(2, 0)) + 1)
#define VE_GET_PORT_NUM(e)	((e) >> 16)
#define VE_IS_IO_STRING(e)	((e) & BIT(4))

static struct {
	unsigned int gpa_width;
	unsigned long attributes;
} td_info __ro_after_init;

/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = fn,
		.r12 = r12,
		.r13 = r13,
		.r14 = r14,
		.r15 = r15,
	};

	return __tdx_hypercall(&args, 0);
}

static inline void tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
				   struct tdx_module_output *out)
{
	if (__tdx_module_call(fn, rcx, rdx, r8, r9, out))
		panic("TDCALL %lld failed (Buggy TDX module!)\n", fn);
}

static void get_info(void)
{
	struct tdx_module_output out;

	/*
	 * TDINFO TDX module call is used to get the TD execution environment
	 * information like GPA width, number of available vcpus, debug mode
	 * information, etc. More details about the ABI can be found in TDX
	 * Guest-Host-Communication Interface (GHCI), section 2.4.2 TDCALL
	 * [TDG.VP.INFO].
	 */
	tdx_module_call(TDX_GET_INFO, 0, 0, 0, 0, &out);

	td_info.gpa_width = out.rcx & GENMASK(5, 0);
	td_info.attributes = out.rdx;
}

static u64 __cpuidle __halt(const bool irq_disabled, const bool do_sti)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_HLT,
		.r12 = irq_disabled,
	};

	/*
	 * Emulate HLT operation via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section 3.8 TDG.VP.VMCALL<Instruction.HLT>.
	 *
	 * The VMM uses the "IRQ disabled" param to understand IRQ
	 * enabled status (RFLAGS.IF) of the TD guest and to determine
	 * whether or not it should schedule the halted vCPU if an
	 * IRQ becomes pending. E.g. if IRQs are disabled, the VMM
	 * can keep the vCPU in virtual HLT, even if an IRQ is
	 * pending, without hanging/breaking the guest.
	 */
	return __tdx_hypercall(&args, do_sti ? TDX_HCALL_ISSUE_STI : 0);
}

static bool handle_halt(void)
{
	/*
	 * Since non safe halt is mainly used in CPU offlining
	 * and the guest will always stay in the halt state, don't
	 * call the STI instruction (set do_sti as false).
	 */
	const bool irq_disabled = irqs_disabled();
	const bool do_sti = false;

	if (__halt(irq_disabled, do_sti))
		return false;

	return true;
}

void __cpuidle tdx_safe_halt(void)
{
	 /*
	  * For do_sti=true case, __tdx_hypercall() function enables
	  * interrupts using the STI instruction before the TDCALL. So
	  * set irq_disabled as false.
	  */
	const bool irq_disabled = false;
	const bool do_sti = true;

	/*
	 * Use WARN_ONCE() to report the failure.
	 */
	if (__halt(irq_disabled, do_sti))
		WARN_ONCE(1, "HLT instruction emulation failed\n");
}

static bool read_msr(struct pt_regs *regs)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_MSR_READ,
		.r12 = regs->cx,
	};

	/*
	 * Emulate the MSR read via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "TDG.VP.VMCALL<Instruction.RDMSR>".
	 */
	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return false;

	regs->ax = lower_32_bits(args.r11);
	regs->dx = upper_32_bits(args.r11);
	return true;
}

static bool write_msr(struct pt_regs *regs)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_MSR_WRITE,
		.r12 = regs->cx,
		.r13 = (u64)regs->dx << 32 | regs->ax,
	};

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	return !__tdx_hypercall(&args, 0);
}

static bool handle_cpuid(struct pt_regs *regs)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_CPUID,
		.r12 = regs->ax,
		.r13 = regs->cx,
	};

	/*
	 * Emulate the CPUID instruction via a hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI), section titled "VP.VMCALL<Instruction.CPUID>".
	 */
	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return false;

	/*
	 * As per TDX GHCI CPUID ABI, r12-r15 registers contain contents of
	 * EAX, EBX, ECX, EDX registers after the CPUID instruction execution.
	 * So copy the register contents back to pt_regs.
	 */
	regs->ax = args.r12;
	regs->bx = args.r13;
	regs->cx = args.r14;
	regs->dx = args.r15;

	return true;
}

static bool mmio_read(int size, unsigned long addr, unsigned long *val)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_EPT_VIOLATION,
		.r12 = size,
		.r13 = EPT_READ,
		.r14 = addr,
		.r15 = *val,
	};

	if (__tdx_hypercall(&args, TDX_HCALL_HAS_OUTPUT))
		return false;
	*val = args.r11;
	return true;
}

static bool mmio_write(int size, unsigned long addr, unsigned long val)
{
	return !_tdx_hypercall(EXIT_REASON_EPT_VIOLATION, size, EPT_WRITE,
			       addr, val);
}

static bool handle_mmio(struct pt_regs *regs, struct ve_info *ve)
{
	char buffer[MAX_INSN_SIZE];
	unsigned long *reg, val;
	struct insn insn = {};
	enum mmio_type mmio;
	int size, extend_size;
	u8 extend_val = 0;

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return false;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return false;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == MMIO_DECODE_FAILED))
		return false;

	if (mmio != MMIO_WRITE_IMM && mmio != MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return false;
	}

	ve->instr_len = insn.length;

	switch (mmio) {
	case MMIO_WRITE:
		memcpy(&val, reg, size);
		return mmio_write(size, ve->gpa, val);
	case MMIO_WRITE_IMM:
		val = insn.immediate.value;
		return mmio_write(size, ve->gpa, val);
	case MMIO_READ:
	case MMIO_READ_ZERO_EXTEND:
	case MMIO_READ_SIGN_EXTEND:
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		return false;
	default:
		BUG();
	}

	/* Handle reads */
	if (!mmio_read(size, ve->gpa, &val))
		return false;

	switch (mmio) {
	case MMIO_READ:
		/* Zero-extend for 32-bit operation */
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case MMIO_READ_ZERO_EXTEND:
		/* Zero extend based on operand size */
		extend_size = insn.opnd_bytes;
		break;
	case MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	case MMIO_MOVS:
	case MMIO_DECODE_FAILED:
		return false;
	default:
		BUG();
	}

	if (extend_size)
		memset(reg, extend_val, extend_size);
	memcpy(reg, &val, size);
	return true;
}

/*
 * Emulate I/O using hypercall.
 *
 * Assumes the IO instruction was using ax, which is enforced
 * by the standard io.h macros.
 *
 * Return True on success or False on failure.
 */
static bool handle_io(struct pt_regs *regs, u32 exit_qual)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		.r11 = EXIT_REASON_IO_INSTRUCTION,
	};
	int size, port;
	u64 mask;
	bool in, ret;

	if (VE_IS_IO_STRING(exit_qual))
		return false;

	in   = VE_IS_IO_IN(exit_qual);
	size = VE_GET_IO_SIZE(exit_qual);
	port = VE_GET_PORT_NUM(exit_qual);
	mask = GENMASK(BITS_PER_BYTE * size, 0);

	args.r12 = size;
	args.r13 = !in;
	args.r14 = port;
	args.r15 = in ? 0 : regs->ax;

	/*
	 * Emulate the I/O read/write via hypercall. More info about
	 * ABI can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.IO>".
	 */
	ret = !__tdx_hypercall(&args, in ? TDX_HCALL_HAS_OUTPUT : 0);
	if (!ret || !in)
		return ret;

	regs->ax &= ~mask;
	regs->ax |= ret ? args.r11 & mask : UINT_MAX;

	return ret;
}

void tdx_get_ve_info(struct ve_info *ve)
{
	struct tdx_module_output out;

	/*
	 * Retrieve the #VE info from the TDX module, which also clears the "#VE
	 * valid" flag.  This must be done before anything else as any #VE that
	 * occurs while the valid flag is set, i.e. before the previous #VE info
	 * was consumed, is morphed to a #DF by the TDX module.  Note, the TDX
	 * module also treats virtual NMIs as inhibited if the #VE valid flag is
	 * set, e.g. so that NMI=>#VE will not result in a #DF.
	 */
	tdx_module_call(TDX_GET_VEINFO, 0, 0, 0, 0, &out);

	ve->exit_reason = out.rcx;
	ve->exit_qual   = out.rdx;
	ve->gla         = out.r8;
	ve->gpa         = out.r9;
	ve->instr_len   = lower_32_bits(out.r10);
	ve->instr_info  = upper_32_bits(out.r10);
}

/*
 * Handle the user initiated #VE.
 *
 * For example, executing the CPUID instruction from user space
 * is a valid case and hence the resulting #VE has to be handled.
 *
 * For dis-allowed or invalid #VE just return failure.
 */
static bool virt_exception_user(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return false;
	}
}

/* Handle the kernel #VE */
static bool virt_exception_kernel(struct pt_regs *regs, struct ve_info *ve)
{
	switch (ve->exit_reason) {
	case EXIT_REASON_HLT:
		return handle_halt();
	case EXIT_REASON_MSR_READ:
		return read_msr(regs);
	case EXIT_REASON_MSR_WRITE:
		return write_msr(regs);
	case EXIT_REASON_CPUID:
		return handle_cpuid(regs);
	case EXIT_REASON_EPT_VIOLATION:
		return handle_mmio(regs, ve);
	case EXIT_REASON_IO_INSTRUCTION:
		return handle_io(regs, ve->exit_qual);
	default:
		pr_warn("Unexpected #VE: %lld\n", ve->exit_reason);
		return false;
	}
}

bool tdx_handle_virt_exception(struct pt_regs *regs, struct ve_info *ve)
{
	bool ret;

	if (user_mode(regs))
		ret = virt_exception_user(regs, ve);
	else
		ret = virt_exception_kernel(regs, ve);

	/* After successful #VE handling, move the IP */
	if (ret)
		regs->ip += ve->instr_len;

	return ret;
}

void __init tdx_early_init(void)
{
	u32 eax, sig[3];
	u64 mask;

	cpuid_count(TDX_CPUID_LEAF_ID, 0, &eax, &sig[0], &sig[2],  &sig[1]);

	if (memcmp(TDX_IDENT, sig, 12))
		return;

	setup_force_cpu_cap(X86_FEATURE_TDX_GUEST);

	get_info();

	/*
	 * All bits above GPA width are reserved and kernel treats shared bit
	 * as flag, not as part of physical address.
	 *
	 * Adjust physical mask to only cover valid GPA bits.
	 */
	physical_mask &= GENMASK_ULL(td_info.gpa_width - 2, 0);

	/*
	 * The highest bit of a guest physical address is the "sharing" bit.
	 * Set it for shared pages and clear it for private pages.
	 */
	mask = BIT_ULL(td_info.gpa_width - 1);

	cc_init(CC_VENDOR_INTEL, mask);

	pr_info("Guest detected\n");
}
