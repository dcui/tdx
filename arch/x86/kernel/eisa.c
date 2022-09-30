// SPDX-License-Identifier: GPL-2.0-only
/*
 * EISA specific code
 */
#include <linux/ioport.h>
#include <linux/eisa.h>
#include <linux/io.h>

#include <xen/xen.h>

static __init int eisa_bus_probe(void)
{
#if 0

	void __iomem *p;

	if (xen_pv_domain() && !xen_initial_domain())
		return 0;

	p = ioremap(0x0FFFD9, 4);
	if (p && readl(p) == 'E' + ('I' << 8) + ('S' << 16) + ('A' << 24))
		EISA_bus = 1;
	iounmap(p);
#endif
	printk("cdx: eisa_bus_probe is noop\n");
	return 0;
}
subsys_initcall(eisa_bus_probe);
