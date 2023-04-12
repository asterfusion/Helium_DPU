#  Copyright (C) 2018 Marvell International Ltd.
#
# This program is provided "as is" without any warranty of any kind, and is
# distributed under the applicable Marvell proprietary limited use license
# agreement.

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_lport.a

CFLAGS += -O3
# Use general WERROR_FLAGS but do not warn about use of functions
# marked as deprecated since we want to use ownership related api which
# currently is marked so ("experimental")
CFLAGS += $(WERROR_FLAGS) -Wno-deprecated-declarations
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_cfgfile
LDLIBS += -lrte_bus_vdev

EXPORT_MAP := rte_pmd_lport_version.map

LIBABIVER := 1

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_LPORT) += rte_eth_lport_pmd.c

include $(RTE_SDK)/mk/rte.lib.mk
