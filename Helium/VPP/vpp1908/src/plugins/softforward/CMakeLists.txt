add_vpp_plugin(softforward
  SOURCES
  plugin.c
  softforward.c
  softforward_proc.c
  softforward_cli.c
  asic_priv.c
  asic_priv_proc.c
  asic_priv_cli.c


  MULTIARCH_SOURCES
  softforward_proc.c
  asic_priv_proc.c

  API_FILES

  API_TEST_SOURCES

  INSTALL_HEADERS
)
