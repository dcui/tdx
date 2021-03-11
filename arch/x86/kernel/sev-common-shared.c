// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * Copyright (C) 2021 Advanced Micro Devices, Inc.
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases.
 */

static void sev_es_terminate(unsigned int reason)
{
	u64 val = GHCB_SEV_TERMINATE;

	/*
	 * Tell the hypervisor what went wrong - only reason-set 0 is
	 * currently supported.
	 */
	val |= GHCB_SEV_TERMINATE_REASON(0, reason);

	/* Request Guest Termination from Hypvervisor */
	sev_es_wr_ghcb_msr(val);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n" : : : "memory");
}

