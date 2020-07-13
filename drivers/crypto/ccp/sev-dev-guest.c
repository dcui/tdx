// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Secure Encrypted Virtualization Nested Paging (SEV-SNP) guest request interface
 *
 * Copyright (C) 2020 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/mem_encrypt.h>
#include <linux/psp-sev-guest.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/set_memory.h>
#include <linux/mm.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/random.h>

#define DEVICE_NAME		"sev"
#define AAD_LEN			48
#define MAX_AUTHTAG_LEN		32

MODULE_AUTHOR("Brijesh Singh <brijesh.singh@amd.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1.0");
MODULE_DESCRIPTION("AMD Secure Encrypted Guest Driver");

struct sev_guest_crypto {
	struct crypto_aead *tfm;
	char *iv, *authtag;
	int iv_len, a_len;
};

struct sev_guest_misc_dev {
	struct sev_guest_crypto *crypto;
	unsigned long response;		/* response message page */
	unsigned long request;		/* request message page */
	struct miscdevice misc;
};

static DEFINE_MUTEX(sev_cmd_mutex);
static struct sev_guest_misc_dev *misc_dev;

static uint32_t msg_seqno = 1; /* TODO: get/set the seqnumber in the ACPI table */

struct secret_page {
	uint32_t version;
	uint32_t imiEn:1;
	uint32_t rsvd1:31;
	uint8_t rsvd2[24];
	uint8_t vmpck0[32];
	uint8_t vmpck1[32];
	uint8_t vmpck2[32];
	uint8_t vmpck3[32];
	uint8_t rsvd3[3936];
};

static int enc_dec_message(struct snp_guest_request_msg_hdr *hdr, uint8_t *src_buf,
			   uint8_t *dst_buf, uint8_t *iv, uint32_t len, bool enc)
{
	struct sev_guest_crypto *crypto = misc_dev->crypto;
	struct scatterlist src[3], dst[3];
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	int ret;

	req = aead_request_alloc(crypto->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/*
	 * AEAD memory operations:
	 * +------ AAD -------+------- DATA -----+---- AUTHTAG----+
	 * |  msg header      |  plaintext       |  hdr->authtag  |
	 * | bytes 30h - 5Fh  |    or            |                |
	 * |                  |   cipher         |                |
	 * +------------------+------------------+----------------+
	 */
	sg_init_table(src, 3);
	sg_set_buf(&src[0], &hdr->algo, AAD_LEN);
	sg_set_buf(&src[1], src_buf, hdr->msg_sz);
	sg_set_buf(&src[2], hdr->authtag, crypto->a_len);

	sg_init_table(dst, 3);
	sg_set_buf(&dst[0], &hdr->algo, AAD_LEN);
	sg_set_buf(&dst[1], dst_buf, hdr->msg_sz);
	sg_set_buf(&dst[2], hdr->authtag, crypto->a_len);

	aead_request_set_ad(req, AAD_LEN);
	aead_request_set_tfm(req, crypto->tfm);
	aead_request_set_callback(req, 0, crypto_req_done, &wait);

	aead_request_set_crypt(req, src, dst, len, iv);
	ret = crypto_wait_req(enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req), &wait);

	aead_request_free(req);
	return ret;
}

static int build_request_message(void __user *plaintext, int msg_type,
				 int msg_version, uint32_t len)
{
	struct sev_guest_crypto *crypto = misc_dev->crypto;
	struct snp_guest_request_msg_hdr *hdr;
	uint8_t *buf, *payload;
	int ret;

	buf = kmalloc(len, GFP_KERNEL_ACCOUNT);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, plaintext, len)) {
		ret = -EFAULT;
		goto e_free;
	}

	hdr = (struct snp_guest_request_msg_hdr *)misc_dev->request;
	payload = (uint8_t *)misc_dev->request + sizeof(*hdr);
	memset(hdr, 0, sizeof(*hdr));
	hdr->algo = SNP_AEAD_AES_256_GCM;
	hdr->hdr_version = 1;
	hdr->hdr_sz = sizeof(*hdr);
	hdr->msg_type = msg_type;
	hdr->msg_seqno = msg_seqno;
	hdr->msg_sz = len;
	hdr->msg_vmpck = 0;
	hdr->msg_version = msg_version;

	/* Generate a random IV for the encryption */
	get_random_bytes(hdr->iv, min_t(size_t, crypto->iv_len, sizeof(hdr->iv)));

	/* Encrypt the request payload */
	ret = enc_dec_message(hdr, buf, payload, hdr->iv, len, true);

e_free:
	kfree(buf);
	return ret;
}

static int verify_response_message(int msg_type, int msg_version, int *msg_sz, void *plaintext)
{
	struct sev_guest_crypto *crypto = misc_dev->crypto;
	struct snp_guest_request_msg_hdr *hdr;
	uint8_t *payload;
	int ret;

	hdr = (struct snp_guest_request_msg_hdr *)misc_dev->response;
	payload = (uint8_t *)misc_dev->response + sizeof(*hdr);

	/* Decrypt the response payload */
	ret = enc_dec_message(hdr, payload, plaintext, hdr->iv,
				min_t(size_t, hdr->msg_sz, *msg_sz) + crypto->a_len, false);

	/* Verify the sequence counter is incremented by 1 */
	if (hdr->msg_seqno != (msg_seqno + 1))
		return -EBADMSG;

	/* Save the message counter for the next request */
	msg_seqno = hdr->msg_seqno + 1;

	/* Verify response type and version number */
	if ((hdr->msg_type != msg_type) || (hdr->msg_version != msg_version))
		return -EBADMSG;

	/* If the message size is greather than out buffer length then return an error. */
	if (unlikely(hdr->msg_sz > *msg_sz))
		return -EBADMSG;

	return 0;
}

static int expected_buf_sz(int type)
{
	switch(type) {
	case SNP_MSG_KEY_REQ: return SEV_SNP_KEY_REQ_BUF_SZ;
	case SNP_MSG_KEY_RSP: return SEV_SNP_KEY_RSP_BUF_SZ;
	case SNP_MSG_REPORT_REQ: return SEV_SNP_REPORT_REQ_BUF_SZ;
	case SNP_MSG_REPORT_RSP: return SEV_SNP_REPORT_RSP_BUF_SZ;
	case SNP_MSG_EXPORT_REQ: return SEV_SNP_EXPORT_REQ_BUF_SZ;
	case SNP_MSG_EXPORT_RSP: return SEV_SNP_REPORT_RSP_BUF_SZ;
	case SNP_MSG_IMPORT_REQ: return SEV_SNP_IMPORT_REQ_BUF_SZ;
	case SNP_MSG_IMPORT_RSP: return SEV_SNP_IMPORT_RSP_BUF_SZ;
	case SNP_MSG_ABSORB_REQ: return SEV_SNP_ABSORB_REQ_BUF_SZ;
	case SNP_MSG_ABSORB_RSP: return SEV_SNP_ABSORB_REQ_BUF_SZ;
	case SNP_MSG_VMRK_REQ:	return SEV_SNP_VMRK_REQ_BUF_SZ;
	case SNP_MSG_VMRK_RSP:	return SEV_SNP_VMRK_REQ_BUF_SZ;
	default: return (PAGE_SIZE - sizeof(struct snp_guest_request_msg_hdr));
	}
}

static int ioctl_snp_guest_request(struct sev_snp_guest_request *input)
{
	uint8_t *rsp_buf;
	int ret, rsp_len;

	if ((input->request_len > expected_buf_sz(input->req_msg_type)) ||
	    (input->response_len < expected_buf_sz(input->rsp_msg_type)))
		return -EINVAL;

	/*
	 * TODO:
	 * 1) add some access control based on the message type.
	 * 2) do we need to limit the message type request that can be requested
	 *    by the userspace (e.g EXPORT, IMPORT, CPUID etc)
	 */
	if (!access_ok(input->response_uaddr, input->response_len))
		return -EFAULT;

	rsp_len = input->response_len;
	rsp_buf = kmalloc(rsp_len, GFP_KERNEL_ACCOUNT);
	if (!rsp_buf)
		return -ENOMEM;

	/* Build the request message per SNP specification */
	ret = build_request_message((void __user *)input->request_uaddr, input->req_msg_type,
				    input->msg_version, input->request_len);
	if (ret)
		goto e_free;

	/* Issue the VMGEXIT to formware the request to the SEV firmware. */
	ret = vmgexit_snp_guest_request(misc_dev->request, misc_dev->response);
	if (ret) {
		/* propogate the error code to userspace */
		input->error = ret;
		return ret;
	}

	/* Now that the VMGEXIT is succesfull, verify the response header */
	ret = verify_response_message(input->rsp_msg_type, input->msg_version, &rsp_len, rsp_buf);
	if (ret)
		goto e_free;

	/* Copy the response payload back to userspace */
	if (copy_to_user((void __user *)input->response_uaddr, rsp_buf, rsp_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	input->response_len = rsp_len;
e_free:
	kfree(rsp_buf);
	return ret;
}

static long sev_guest_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct sev_snp_guest_request input;
	int ret = -ENOTTY;

	if (copy_from_user(&input, argp, sizeof (struct sev_snp_guest_request)))
		return -EFAULT;

	mutex_lock(&sev_cmd_mutex);

	switch(ioctl) {

	case SEV_SNP_GUEST_MSG_REQUEST: {
		if (!capable(CAP_SYS_ADMIN)) {
			mutex_unlock(&sev_cmd_mutex);
			return -EACCES;
		}

		ret = ioctl_snp_guest_request(&input);
		break;
	}
	case SEV_SNP_GUEST_MSG_REPORT: {
		input.req_msg_type = SNP_MSG_REPORT_REQ;
		input.rsp_msg_type = SNP_MSG_REPORT_RSP;
		input.msg_version = 1;

		ret = ioctl_snp_guest_request(&input);
		break;
	}
	case SEV_SNP_GUEST_MSG_KEY: {
		input.req_msg_type = SNP_MSG_KEY_REQ;
		input.rsp_msg_type = SNP_MSG_KEY_RSP;
		input.msg_version = 1;

		ret = ioctl_snp_guest_request(&input);
		break;
	}
	default: break;
	}

	mutex_unlock(&sev_cmd_mutex);
	if (copy_to_user(argp, &input, sizeof(struct sev_snp_guest_request)))
		ret = -EFAULT;

	return ret;
}

static const struct file_operations sev_guest_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_guest_ioctl,
};

static void free_shared_page(unsigned long page)
{
	set_memory_encrypted(page, 1);
	free_page(page);
}

static unsigned long alloc_shared_page(void)
{
	unsigned long page;
	int ret;

	page = get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!page)
		return page;

	if ((ret = set_memory_decrypted(page, 1))) {
		free_page(page);
		return ret;
	}

	return page;
}

static struct sev_guest_crypto *init_crypto(void)
{
	struct sev_guest_crypto *crypto;
	struct secret_page *secret;

	/*
	 * TODO: find the VMPCK and message sequence number through ACPI table.
	 * Currently, we map the secret page directly to get the VMPCK to test the driver flow.
	 */
	secret = (struct secret_page *)memremap(0x801000, PAGE_SIZE, MEMREMAP_WB);
	if (!secret) {
		pr_err("failed to remap 0x801000.\n");
		return NULL;
	}

	crypto = kzalloc(sizeof(*crypto), GFP_KERNEL_ACCOUNT);
	if (!crypto)
		return NULL;

	crypto->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(crypto->tfm))
		goto e_free;

	if (crypto_aead_setkey(crypto->tfm, secret->vmpck0, 32))
		goto e_free_crypto;

	crypto->iv_len = crypto_aead_ivsize(crypto->tfm);
	crypto->iv = kmalloc(crypto->iv_len, GFP_KERNEL_ACCOUNT);
	if (!crypto->iv)
		goto e_free_crypto;

	if (crypto_aead_authsize(crypto->tfm) > MAX_AUTHTAG_LEN) {
		if (crypto_aead_setauthsize(crypto->tfm, MAX_AUTHTAG_LEN)) {
			pr_err("Failed to set authsize to %d\n", MAX_AUTHTAG_LEN);
			goto e_free_crypto;
		}
	}

	crypto->a_len = crypto_aead_authsize(crypto->tfm);
	crypto->authtag = kmalloc(crypto->a_len, GFP_KERNEL_ACCOUNT);
	if (!crypto->authtag)
		goto e_free_crypto;


	pr_info("MSG sequence counter: %d\n", msg_seqno);
	print_hex_dump(KERN_INFO, "VMPCK0 KEY : ", DUMP_PREFIX_NONE, 32, 1, secret->vmpck0, 32, false);

	return crypto;
e_free_crypto:
	crypto_free_aead(crypto->tfm);
e_free:
	kfree(crypto->iv);
	kfree(crypto->authtag);
	kfree(crypto);
	return NULL;
}

static void deinit_crypto(struct sev_guest_crypto *crypto)
{
	if (!crypto)
		return;

	crypto_free_aead(crypto->tfm);
	kfree(crypto->iv);
	kfree(crypto->authtag);
	kfree(crypto);
}

static int __init sev_guest_mod_init(void)
{
	struct miscdevice *misc;
	int ret;

	if (!mem_encrypt_active())
		return -ENXIO;

	misc_dev = kzalloc(sizeof(*misc_dev), GFP_KERNEL);
	if (!misc_dev)
		return -ENOMEM;

	misc_dev->response = alloc_shared_page();
	if (!misc_dev->response) {
		ret = misc_dev->response;
		goto e_free;
	}

	misc_dev->request = alloc_shared_page();
	if (!misc_dev->request) {
		ret = misc_dev->request;
		goto e_free;
	}

	misc_dev->crypto = init_crypto();
	if (!misc_dev->crypto) {
		ret = -EINVAL;
		goto e_free;
	}

	misc = &misc_dev->misc;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = DEVICE_NAME;
	misc->fops = &sev_guest_fops;

	return misc_register(misc);
e_free:
	if (misc_dev->response)
		free_shared_page(misc_dev->response);
	if (misc_dev->request)
		free_shared_page(misc_dev->request);
	kfree(misc_dev);
	misc_dev = NULL;
	return ret;
}

static void __exit sev_guest_mod_exit(void)
{
	if (!misc_dev)
		return;

	free_shared_page(misc_dev->request);
	free_shared_page(misc_dev->response);
	deinit_crypto(misc_dev->crypto);
	misc_deregister(&misc_dev->misc);
	kfree(misc_dev);
}

module_init(sev_guest_mod_init);
module_exit(sev_guest_mod_exit);
