# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.
#

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec = 'l2fwd-event-pfc'

allow_experimental_apis = true
deps += 'eventdev'

# Create the test executable
l2fwd_event_pfc_test=executable(
    test_exec,
    files('main.c', 'l2fwd_common.c', 'l2fwd_event.c',
          'l2fwd_event_generic.c', 'l2fwd_event_internal_port.c',
          'l2fwd_poll.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: 'bin/cnxk/l2fwd_event_pfc',
    install: true,
)
