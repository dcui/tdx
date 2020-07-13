/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Secure Encrypted Virtualization (SEV) driver interface
 *
 * Copyright (C) 2020 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV API spec is available at https://developer.amd.com/sev
 */

#ifndef __PSP_SEV_GUEST_H__
#define __PSP_SEV_GUEST_H__

#include <linux/types.h>
#include <uapi/linux/psp-sev-guest.h>

/**
 * snp_guest_request_msg_header - SNP guest message request header
 */
struct snp_guest_request_msg_hdr {
	__u8 authtag[32];
	__u8 iv[16];
	__u8 algo;
	__u8 hdr_version;
	__u16 hdr_sz;
	__u8 msg_type;
	__u8 msg_version;
	__u16 msg_sz;
	__u32 msg_seqno;
	__u8 msg_vmpck;
	__u8 rsvd[35];
} __packed;

/**
 * AEAD algorithm encoding type
 */
enum snp_aead_algo {
	SNP_AEAD_INVALID,
	SNP_AEAD_AES_256_GCM,
};

#ifdef CONFIG_AMD_MEM_ENCRYPT

int vmgexit_snp_guest_request(unsigned long request, unsigned long response);

#else
static inline int vmgexit_snp_guest_request(unsigned long request, unsigned long response)
{
	return -ENXIO;
}

#endif

#endif /* PSP_SEV_GUEST */
