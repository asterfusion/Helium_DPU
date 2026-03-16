add_vpp_plugin(ha_sync
  SOURCES
  ha_sync.c
  ha_sync_buffer.c
  ha_sync_pool.c
  ha_sync_protocol.c
  ha_sync_test.c
  node.c

  INSTALL_HEADERS
  ha_sync.h
)
