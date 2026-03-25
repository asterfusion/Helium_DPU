add_vpp_plugin(ha_sync
  SOURCES
  ha_sync.c
  ha_sync_api.c
  ha_sync_buffer.c
  ha_sync_pool.c
  ha_sync_protocol.c
  ha_sync_test.c
  node.c
  ../hqos/fifo/fifo.c

  API_FILES
  ha_sync.api

  INSTALL_HEADERS
  ha_sync.h
)
