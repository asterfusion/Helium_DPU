# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Marvell International Ltd.
# Copyright(c) 2017 Semihalf.
# All rights reserved.

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),config)
ifeq ($(LIBMUSDK_PATH),)
$(error "Please define LIBMUSDK_PATH environment variable")
endif
endif
endif

# library name
LIB = librte_pmd_mvgiu.a

# library version
LIBABIVER := 1

# versioning export map
EXPORT_MAP := rte_pmd_mvgiu_version.map

# external library dependencies
CFLAGS += -I$(RTE_SDK)/drivers/common/mvep
CFLAGS += -I$(LIBMUSDK_PATH)/include
CFLAGS += -DMVCONF_TYPES_PUBLIC
CFLAGS += -DMVCONF_DMA_PHYS_ADDR_T_PUBLIC
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -O3
LDLIBS += -L$(LIBMUSDK_PATH)/lib
LDLIBS += -lmusdk
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_cfgfile
LDLIBS += -lrte_bus_vdev -lrte_common_mvep

# library source files
SRCS-$(CONFIG_RTE_LIBRTE_MVGIU_PMD) += mvgiu_ethdev.c

include $(RTE_SDK)/mk/rte.lib.mk
