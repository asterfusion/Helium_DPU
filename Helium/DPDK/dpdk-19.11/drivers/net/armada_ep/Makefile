# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.
#

include $(RTE_SDK)/mk/rte.vars.mk

# Library name
LIB = librte_pmd_armada_ep.a

# Build flags
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

CFLAGS += -I$(RTE_SDK)/drivers/net/armada_ep/

LDLIBS += -lrte_eal -lrte_net -lrte_ethdev -lrte_bus_pci
LDLIBS += -lrte_bus_vdev -lrte_kvargs -lrte_mbuf  -lrte_mempool

ifneq ($(CONFIG_RTE_ARCH_64),y)
CFLAGS += -Wno-int-to-pointer-cast
CFLAGS += -Wno-pointer-to-int-cast
ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS += -diag-disable 2259
endif
endif

EXPORT_MAP := rte_pmd_armada_ep_version.map

LIBABIVER := 1

#
# All source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_ARMADA_EP_PMD) += armada_ep_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_ARMADA_EP_PMD) += armada_ep_mng.c
SRCS-$(CONFIG_RTE_LIBRTE_ARMADA_EP_PMD) += armada_ep_irq.c

include $(RTE_SDK)/mk/rte.lib.mk
