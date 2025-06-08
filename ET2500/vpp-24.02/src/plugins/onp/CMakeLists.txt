# Copyright (c) 2021 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html
#

if (NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    message ("OCTEON Native plugin (onp) is disabled on non Aarch64 targets")
    return ()
endif()

if (${VPP_PLATFORM_NAME} MATCHES "octeon10")
  add_compile_definitions(VPP_PLATFORM_OCTEON10)
elseif (${VPP_PLATFORM_NAME} MATCHES "octeon9")
  add_compile_definitions(VPP_PLATFORM_OCTEON9)
else()
    message ("-- Unable to detect platform - OCTEON Native plugin (onp) is disabled")
    return ()
endif()

if (${ASROUTER_NAME} MATCHES "octeon10")
  add_compile_definitions(VPP_PLATFORM_ET2500)
endif()

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/drv/roc/base/)
include_directories (${CMAKE_CURRENT_SOURCE_DIR}/drv/roc/)

set(CNXK_DRV_SRCS
  drv/roc/base/roc_ae.c
  drv/roc/base/roc_ae_fpm_tables.c
  drv/roc/base/roc_aes.c
  drv/roc/base/roc_bphy.c
  drv/roc/base/roc_bphy_cgx.c
  drv/roc/base/roc_bphy_irq.c
  drv/roc/base/roc_cpt.c
  drv/roc/base/roc_cpt_debug.c
  drv/roc/base/roc_dev.c
  #drv/roc/base/roc_dpi.c
  drv/roc/base/roc_hash.c
  drv/roc/base/roc_idev.c
  drv/roc/base/roc_ie_ot.c
  drv/roc/base/roc_irq.c
  drv/roc/base/roc_mbox.c
  #drv/roc/base/roc_mcs.c
  #drv/roc/base/roc_mcs_sec_cfg.c
  #drv/roc/base/roc_mcs_stats.c
  #drv/roc/base/roc_ml.c
  drv/roc/base/roc_model.c
  drv/roc/base/roc_nix.c
  drv/roc/base/roc_nix_bpf.c
  drv/roc/base/roc_nix_debug.c
  drv/roc/base/roc_nix_fc.c
  drv/roc/base/roc_nix_inl.c
  drv/roc/base/roc_nix_inl_dev.c
  drv/roc/base/roc_nix_inl_dev_irq.c
  drv/roc/base/roc_nix_irq.c
  drv/roc/base/roc_nix_mac.c
  drv/roc/base/roc_nix_mcast.c
  drv/roc/base/roc_nix_npc.c
  drv/roc/base/roc_nix_ops.c
  drv/roc/base/roc_nix_ptp.c
  drv/roc/base/roc_nix_queue.c
  drv/roc/base/roc_nix_rss.c
  drv/roc/base/roc_nix_stats.c
  drv/roc/base/roc_nix_tm_mark.c
  drv/roc/base/roc_nix_tm_utils.c
  drv/roc/base/roc_nix_vlan.c
  drv/roc/base/roc_npa.c
  drv/roc/base/roc_npa_debug.c
  drv/roc/base/roc_npa_irq.c
  drv/roc/base/roc_npa_type.c
  drv/roc/base/roc_npc.c
  #drv/roc/base/roc_npc_aging.c
  drv/roc/base/roc_npc_mcam.c
  drv/roc/base/roc_npc_mcam_dump.c
  drv/roc/base/roc_npc_parse.c
  drv/roc/base/roc_npc_utils.c
  drv/roc/base/roc_platform.c
  #drv/roc/base/roc_ree.c
  drv/roc/base/roc_se.c
  drv/roc/base/roc_sso.c
  drv/roc/base/roc_sso_debug.c
  drv/roc/base/roc_sso_irq.c
  drv/roc/base/roc_tim.c
  drv/roc/base/roc_tim_irq.c
  drv/roc/base/roc_utils.c

  drv/roc/init.c
  drv/modules/pktio/pktio_cn9k.c
  drv/modules/pktio/pktio_inl_dev_cn10k.c
  drv/modules/pktio/pktio_cnxk.c
  drv/modules/pktio/pktio_flow.c

  drv/modules/sched/sched_cn10k.c
  drv/modules/sched/sched_cnxk.c

  drv/modules/pool/pool_cn9k.c
  drv/modules/pool/pool_cn10k.c
  drv/modules/pool/pool_cnxk.c

  drv/modules/pci/pci.c

  drv/modules/crypto/crypto_cn10k.c
  drv/modules/crypto/crypto_cnxk.c

  drv/modules/ipsec/ipsec_cn10k.c
  drv/modules/ipsec/ipsec_session_cn10k.c
  drv/modules/ipsec/ipsec_cnxk.c
)

if (${ASROUTER_NAME} MATCHES "octeon10")
    list(APPEND CNXK_DRV_SRCS
        drv/roc/base/roc_nix_tm_et2500.c
        drv/roc/base/roc_nix_tm_ops_et2500.c
        drv/modules/pktio/pktio_cn10k_et2500.c
    )
else()
    list(APPEND CNXK_DRV_SRCS
        drv/roc/base/roc_nix_tm.c
        drv/roc/base/roc_nix_tm_ops.c
        drv/modules/pktio/pktio_cn10k.c
    )
endif()

set(CNXK_DRV_HEADERS
  drv/roc/base/roc_nix_inl.h
  drv/roc/base/roc_nix.h
  drv/roc/base/roc_model.h
  drv/roc/base/roc_mbox_priv.h
  drv/roc/base/roc_mbox.h
  drv/roc/base/roc_io_generic.h
  drv/roc/base/roc_io.h
  drv/roc/base/roc_ie_ot.h
  drv/roc/base/roc_ie_on.h
  drv/roc/base/roc_ie.h
  drv/roc/base/roc_idev_priv.h
  drv/roc/base/roc_idev.h
  drv/roc/base/roc_hash.h
  drv/roc/base/roc_features.h
  drv/roc/base/roc_errata.h
  drv/roc/base/roc_dpi_priv.h
  drv/roc/base/roc_dpi.h
  drv/roc/base/roc_dev_priv.h
  drv/roc/base/roc_cpt_sg.h
  drv/roc/base/roc_cpt_priv.h
  drv/roc/base/roc_cpt.h
  drv/roc/base/roc_constants.h
  drv/roc/base/roc_bphy_irq.h
  drv/roc/base/roc_bphy_cgx_priv.h
  drv/roc/base/roc_bphy_cgx.h
  drv/roc/base/roc_bphy.h
  drv/roc/base/roc_bits.h
  drv/roc/base/roc_bitfield.h
  drv/roc/base/roc_api.h
  drv/roc/base/roc_aes.h
  drv/roc/base/roc_ae_fpm_tables.h
  drv/roc/base/roc_ae.h
  drv/roc/base/roc_utils.h
  drv/roc/base/roc_util_priv.h
  drv/roc/base/roc_tim_priv.h
  drv/roc/base/roc_tim.h
  drv/roc/base/roc_sso_priv.h
  drv/roc/base/roc_sso_dp.h
  drv/roc/base/roc_sso.h
  drv/roc/base/roc_se.h
  drv/roc/base/roc_ree_priv.h
  drv/roc/base/roc_ree.h
  drv/roc/base/roc_priv.h
  drv/roc/base/roc_platform.h
  drv/roc/base/roc_npc_priv.h
  drv/roc/base/roc_npc.h
  drv/roc/base/roc_npa_dp.h
  drv/roc/base/roc_npa_priv.h
  drv/roc/base/roc_npa.h
  drv/roc/base/roc_nix_xstats.h
  drv/roc/base/roc_nix_priv.h
  drv/roc/base/roc_nix_inl_priv.h
  drv/roc/base/roc_nix_inl_dp.h
  drv/roc/base/roc_mcs.h
  drv/roc/base/roc_mcs_priv.h
  drv/roc/base/roc_ml.h
  drv/roc/base/roc_ml_priv.h
  drv/roc/base/hw/tim.h
  drv/roc/base/hw/ssow.h
  drv/roc/base/hw/sso.h
  drv/roc/base/hw/sdp.h
  drv/roc/base/hw/rvu.h
  drv/roc/base/hw/ree.h
  drv/roc/base/hw/npc.h
  drv/roc/base/hw/npa.h
  drv/roc/base/hw/nix.h
  drv/roc/base/hw/ml.h
  drv/roc/base/hw/dpi.h
  drv/roc/base/hw/cpt.h
)

if (${ASROUTER_NAME} MATCHES "octeon10")
add_vpp_library(cnxk-roc
  SOURCES ${CNXK_DRV_SRCS}
  INSTALL_HEADERS ${CNXK_DRV_HEADERS}

  MULTIARCH_SOURCES
  drv/modules/pktio/pktio_cn9k.c
  drv/modules/pktio/pktio_cn10k_et2500.c
)
else()
add_vpp_library(cnxk-roc
  SOURCES ${CNXK_DRV_SRCS}
  INSTALL_HEADERS ${CNXK_DRV_HEADERS}

  MULTIARCH_SOURCES
  drv/modules/pktio/pktio_cn9k.c
  drv/modules/pktio/pktio_cn10k.c
)
endif()

add_vpp_plugin(onp
  SOURCES
  onp.c
  format.c
  cli.c
  api/api.c

  pool/buffer.c
  pool/cli.c

  pktio/cli.c
  pktio/pktio.c
  pktio/format.c
  pktio/input.c
  pktio/output.c
  pktio/flow.c
  pktio/tm.c

  sched/input.c
  sched/sched.c
  sched/format.c
  sched/cli.c

  crypto/crypto.c
  ipsec/esp_encrypt.c
  ipsec/esp_decrypt.c
  ipsec/ipsec.c
  dpu/dpu.c

  MULTIARCH_SOURCES
  pktio/input.c
  pktio/output.c
  sched/input.c
  ipsec/esp_encrypt.c
  ipsec/esp_decrypt.c

  LINK_LIBRARIES
  cnxk-roc

  API_FILES
  api/types.api
  api/onp.api

  API_TEST_SOURCES
  api/api_test.c
)

set(VPP_DIR ${CMAKE_SOURCE_DIR}/..)
install(DIRECTORY ${VPP_DIR}/test/ DESTINATION test/ COMPONENT vpp-plugin-onp)
install(DIRECTORY test/ DESTINATION test/unittest/ COMPONENT vpp-plugin-onp)
install(FILES onp-startup.conf DESTINATION etc/vpp/ COMPONENT vpp-plugin-onp)
