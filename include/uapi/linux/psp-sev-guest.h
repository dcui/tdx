/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Userspace interface for AMD Secure Encrypted Virtualization Nested Paging (SEV-SNP)
 * guest command request.
 *
 * Copyright (C) 2020 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV-SNP API specification is available at: https://developer.amd.com/sev/
 */

#ifndef __PSP_USER_SEV_GUEST_H__
#define __PSP_USER_SEV_GUEST_H__

#include <linux/types.h>

#define SEV_SNP_REPORT_REQ_BUF_SZ	96
#define SEV_SNP_REPORT_RSP_BUF_SZ	1280

#define SEV_SNP_KEY_REQ_BUF_SZ		32
#define SEV_SNP_KEY_RSP_BUF_SZ		64

#define SEV_SNP_EXPORT_REQ_BUF_SZ	16
#define SEV_SNP_EXPORT_RSP_BUF_SZ	768

#define SEV_SNP_IMPORT_REQ_BUF_SZ	768
#define SEV_SNP_IMPORT_RSP_BUF_SZ	16

#define SEV_SNP_ABSORB_REQ_BUF_SZ	656
#define SEV_SNP_ABSORB_RSP_BUF_SZ	16

#define SEV_SNP_VMRK_REQ_BUF_SZ		64
#define SEV_SNP_VMRK_RSP_BUF_SZ		16

/**
 * snp_guest_request_msg_type - SNP guest message type
 */
enum snp_msg_type {
	SNP_MSG_TYPE_INVALID = 0,
	SNP_MSG_CPUID_REQ,
	SNP_MSG_CPUID_RSP,
	SNP_MSG_KEY_REQ,
	SNP_MSG_KEY_RSP,
	SNP_MSG_REPORT_REQ,
	SNP_MSG_REPORT_RSP,
	SNP_MSG_EXPORT_REQ,
	SNP_MSG_EXPORT_RSP,
	SNP_MSG_IMPORT_REQ,
	SNP_MSG_IMPORT_RSP,
	SNP_MSG_ABSORB_REQ,
	SNP_MSG_ABSORB_RSP,
	SNP_MSG_VMRK_REQ,
	SNP_MSG_VMRK_RSP,

	SNP_MSG_TYPE_MAX
};

struct sev_snp_guest_request {
	__u8 req_msg_type;
	__u8 rsp_msg_type;
	__u8 msg_version;
	__u16 request_len;
	__u64 request_uaddr;
	__u16 response_len;
	__u64 response_uaddr;
	__u32 error;		/* firmware error code on failure (see psp-sev.h) */
};

#define SEV_GUEST_IOC_TYPE		'S'
#define SEV_SNP_GUEST_MSG_REQUEST	_IOWR(SEV_GUEST_IOC_TYPE, 0x0, struct sev_snp_guest_request)
#define SEV_SNP_GUEST_MSG_REPORT	_IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct sev_snp_guest_request)
#define SEV_SNP_GUEST_MSG_KEY		_IOWR(SEV_GUEST_IOC_TYPE, 0x2, struct sev_snp_guest_request)

#endif /* __PSP_USER_SEV_GUEST_H__ */
