add_vpp_plugin(hqos
  SOURCES
  sched/sched_common.c
  sched/approx.c
  sched/reciprocal.c
  sched/red.c
  sched/pie.c
  sched/sched.c

  fifo/fifo.c

  preprocess_node.c
  process_node.c
  postprocess_node.c

  hqos.c
  hqos_api.c
  hqos_cli.c
  hqos_format.c

  MULTIARCH_SOURCES
  preprocess_node.c
  postprocess_node.c
  process_node.c

  API_FILES
  hqos.api

  INSTALL_HEADERS
  sched/sched_common.h
  sched/red.h
  sched/pie.h
  sched/approx.h
  sched/reciprocal.h
  sched/bitmap.h
  sched/sched.h

  fifo/fifo.h
)
