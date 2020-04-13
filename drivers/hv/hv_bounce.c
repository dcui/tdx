// SPDX-License-Identifier: GPL-2.0-only
/*
 * Bounce buffer code for Hyper-V Isolation VM support.
 *
 * Authors:
 *   Sunil Muthuswamy <sunilmut@microsoft.com>
 *   Tianyu Lan <Tianyu.Lan@microsoft.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "hyperv_vmbus.h"

int hv_init_channel_ivm(struct vmbus_channel *channel)
{
	if (!hv_is_isolation_supported())
		return 0;

	INIT_LIST_HEAD(&channel->bounce_page_free_head);
	INIT_LIST_HEAD(&channel->bounce_pkt_free_list_head);

	channel->bounce_pkt_cache = KMEM_CACHE(hv_bounce_pkt, 0);
	if (unlikely(!channel->bounce_pkt_cache))
		return -ENOMEM;
	channel->bounce_page_cache = KMEM_CACHE(hv_bounce_page_list, 0);
	if (unlikely(!channel->bounce_page_cache))
		return -ENOMEM;

	return 0;
}

void hv_free_channel_ivm(struct vmbus_channel *channel)
{
	if (!hv_is_isolation_supported())
		return;


	cancel_delayed_work_sync(&channel->bounce_page_list_maintain);
	hv_bounce_pkt_list_free(channel, &channel->bounce_pkt_free_list_head);
	hv_bounce_page_list_free(channel, &channel->bounce_page_free_head);
	kmem_cache_destroy(channel->bounce_pkt_cache);
	kmem_cache_destroy(channel->bounce_page_cache);
}
