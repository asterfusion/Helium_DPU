# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2025 Marvell.
#

if not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on 64-bit'
    subdir_done()
endif

sources = files('cnxk_emdev.c',
                'cnxk_emdev_virtio.c',
                'cnxk_emdev_vnet.c',
                'cnxk_emdev_vnet_deq.c',
                'cnxk_emdev_vnet_enq.c')

deps += ['rawdev', 'mbuf', 'mempool', 'pci', 'bus_pci']
deps += ['common_cnxk', 'mempool_cnxk']
headers = files('rte_pmd_cnxk_emdev.h', 'spec/virtio.h', 'spec/virtio_net.h')

require_iova_in_mbuf = false
