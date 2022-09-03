// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2004 James Cleverdon, IBM.
 *
 * Generic APIC sub-arch probe layer.
 *
 * Hacked for x86-64 by James Cleverdon from i386 architecture code by
 * Martin Bligh, Andi Kleen, James Bottomley, John Stultz, and
 * James Cleverdon.
 */
#include <linux/thread_info.h>
#include <asm/apic.h>

#include "local.h"

/*
 * Check the APIC IDs in bios_cpu_apicid and choose the APIC mode.
 */
void __init default_setup_apic_routing(void)
{
	struct apic **drv;

	printk("cdx: %s, line %d\n", __func__, __LINE__);
	enable_IR_x2apic();
	printk("cdx: %s, line %d\n", __func__, __LINE__);

	for (drv = __apicdrivers; drv < __apicdrivers_end; drv++) {
		printk("cdx: %s, line %d, drv=%s\n", __func__, __LINE__, (*drv)->name);
		if ((*drv)->probe && (*drv)->probe()) {
			if (apic != *drv) {
				apic = *drv;
				pr_info("Switched APIC routing to %s.\n",
					apic->name);
			}
			break;
		}
	}
}

int __init default_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	struct apic **drv;

	printk("cdx: %s, line %d\n", __func__, __LINE__);
	for (drv = __apicdrivers; drv < __apicdrivers_end; drv++) {
		printk("cdx: %s, line %d, drv=%s, apic=%s\n", __func__, __LINE__, (*drv)->name, apic == NULL ? "NNN" : apic->name);
		if ((*drv)->acpi_madt_oem_check(oem_id, oem_table_id)) {
			if (apic != *drv) {
				apic = *drv;
				pr_info("Setting APIC routing to %s.\n",
					apic->name);
			}
			return 1;
		}
	}
	return 0;
}
