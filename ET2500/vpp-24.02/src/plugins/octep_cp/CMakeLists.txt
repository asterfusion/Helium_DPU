# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html
#

unset(OCTEP_INCLUDE_DIR)
unset(OCTEP_LINK_FLAGS)
unset(OCTEP_LIB_DIR)

set(OCTEP_LIB_DIR_HINT "/usr/marvell")
set(OCTEP_INC_DIR_HINT "/usr/marvell/include")
set(PLAT "aarch64")

if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64.*")
  return()
endif()

vpp_find_path(OCTEP_INCLUDE_DIR octep_cp_lib.h HINTS ${OCTEP_INC_DIR_HINT})
vpp_plugin_find_library(octep_cp OCTEP_LIB "liboctep_cp.a" HINTS ${OCTEP_LIB_DIR_HINT})

if (NOT OCTEP_INCLUDE_DIR)
  message(WARNING "-- Octep headers not found - Octep-cp plugin disabled")
  return()
endif()

if (NOT OCTEP_LIB)
  message(WARNING "-- Octep lib not found - Octep-cp plugin disabled")
  return()
else()
  message(WARNING "-- Octep lib found - Octep-cp plugin enabled")
endif()

set(CMAKE_C_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}/compat/${PLAT}")

get_filename_component(OCTEP_LIB_DIR ${OCTEP_LIB} DIRECTORY)
string_append(OCTEP_LINK_FLAGS "-L${OCTEP_LIB_DIR}")
string_append(OCTEP_LINK_FLAGS "-Wl,--whole-archive,${OCTEP_LIB},-lconfig,--no-whole-archive")

include_directories (${OCTEP_INCLUDE_DIR})

message(STATUS "OCTEP header ${OCTEP_INCLUDE_DIR}")
message(STATUS "OCTEP lib ${OCTEP_LIB_DIR}")
message(STATUS "OCTEP link flag ${OCTEP_LINK_FLAGS}")

add_vpp_plugin(octep_cp
  SOURCES
  octep_ctrl.c
  octep_config.c
  octep_action.c
  octep_input.c
  LINK_FLAGS
  "${OCTEP_LINK_FLAGS}"
)
install(FILES octep_cp_cn10kxx.cfg DESTINATION etc/vpp/ COMPONENT vpp-plugin-octep_cp)
