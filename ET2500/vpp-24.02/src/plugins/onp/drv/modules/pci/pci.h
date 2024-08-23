/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 *
 */

#ifndef included_onp_drv_modules_pci_pci_h
#define included_onp_drv_modules_pci_pci_h

#include <onp/drv/roc/platform.h>
#include <onp/drv/roc/base/roc_api.h>

void *cnxk_pci_dev_probe (vlib_main_t *vm, vlib_pci_addr_t *addr,
			  uuid_t uuid_token, vlib_pci_dev_handle_t *);

#endif /* included_onp_drv_modules_pci_pci_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
