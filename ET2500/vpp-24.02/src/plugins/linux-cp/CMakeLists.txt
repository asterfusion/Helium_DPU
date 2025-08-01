# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

vpp_find_path(LIBNL3_INCLUDE_DIR NAMES libnl3/netlink/route/link/vlan.h)
vpp_find_path(LIBMNL_INCLUDE_DIR NAMES libmnl/libmnl.h)

if (NOT LIBNL3_INCLUDE_DIR)
  message(WARNING "-- libnl3 headers not found - linux-cp plugin disabled")
  return()
endif()

if (NOT LIBMNL_INCLUDE_DIR)
  message(WARNING "-- libmnl headers not found - linux-cp plugin disabled")
  return()
endif()

vpp_plugin_find_library(linux-cp LIBNL3_LIB libnl-3.so)
vpp_plugin_find_library(linux-cp LIBNL3_ROUTE_LIB libnl-route-3.so.200)
vpp_plugin_find_library(linux-cp LIBNL3_XFRM_LIB libnl-xfrm-3.so.200)

include_directories(${LIBNL3_INCLUDE_DIR}/libnl3)
include_directories(${LIBMNL_INCLUDE_DIR})

add_vpp_library(lcp
  SOURCES
  lcp_interface.c
  lcp_interface_sync.c
  lcp_mpls_sync.c
  lcp_adj.c
  lcp.c

  LINK_LIBRARIES
  ${LIBNL3_LIB}
  ${LIBNL3_ROUTE_LIB}

  INSTALL_HEADERS
  lcp_interface.h
  lcp.h
)

add_vpp_plugin(linux_cp
  SOURCES
  lcp_api.c
  lcp_cli.c
  lcp_node.c
  lcp_ospf.c
  lcp_lldp.c
  lcp_lacp.c
  lcp_dhcp.c
  lcp_ndp.c
  lcp_pppoe.c
  lcp_pppoe_api.c
  lcp_bfd.c
  lcp_bpdu.c
  lcp_vrrp.c

  API_FILES
  lcp.api
  lcp_pppoe.api

  LINK_LIBRARIES
  lcp
)

add_vpp_plugin(linux_cp_unittest
  SOURCES
  test/lcp_unittest.c

  LINK_LIBRARIES
  lcp
)

add_vpp_plugin(linux_nl
  SOURCES
  lcp_router.c
  lcp_nl.c
  lcp_ipsec.c
  lcp_xfrm_nl.c

  LINK_LIBRARIES
  ${LIBNL3_XFRM_LIB}
  lcp
)

if (${VPP_PLATFORM_NAME} MATCHES "octeon10")
  add_compile_definitions(ET2500_SET_TC)
  add_compile_definitions(ET2500_NO_NETLINK)
endif()