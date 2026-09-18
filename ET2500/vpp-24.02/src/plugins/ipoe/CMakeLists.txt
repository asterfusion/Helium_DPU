# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(ipoe
  SOURCES
  ipoe.c
  ipoe_api.c
  ipoe_session.c
  ipoe_timer.c
  ipoe_cli.c
  ipoe_l2_input_node.c
  ipoe_ip4_input_node.c
  ipoe_output_node.c

  API_FILES
  ipoe.api
)
