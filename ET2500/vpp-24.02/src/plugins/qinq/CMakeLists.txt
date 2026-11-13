add_vpp_plugin(qinq
  SOURCES
  qinq_api.c
  qinq_cli.c

  API_FILES
  qinq.api

  LINK_LIBRARIES
  ipoe_plugin
)
