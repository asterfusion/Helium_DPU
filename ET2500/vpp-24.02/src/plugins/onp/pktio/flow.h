/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief OCTEON native plugin interface.
 */

#ifndef included_onp_pktio_flow_h
#define included_onp_pktio_flow_h

#include <onp/onp.h>
#include <onp/drv/inc/flow.h>

/*
 * _ (protocol_name, protocol_header, roc_protocol_identifier)
 * third parameter i.e roc_protocol_identifier is enum variable
 * corresponding to the protocol i.e XXX in ROC_NPC_ITEM_TYPE_XXX
 */
#define foreach_cnxk_flow_supported_protocols                                 \
  _ (ethernet, ethernet_header_t, ETH)                                        \
  _ (vlan, ethernet_vlan_header_t, VLAN)                                      \
  _ (ip4, ip4_header_t, IPV4)                                                 \
  _ (ip6, ip6_header_t, IPV6)                                                 \
  _ (udp, udp_header_t, UDP)                                                  \
  _ (tcp, tcp_header_t, TCP)                                                  \
  _ (sctp, cnxk_drv_sctp_header_t, SCTP)                                      \
  _ (esp, esp_header_t, ESP)

u8 *format_flow_error (u8 *s, va_list *args);
#endif /* included_onp_pktio_flow_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
