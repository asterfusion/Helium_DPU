# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

extra_ldflags = []
tmc_dep = dependency('libtmc', required: false, method: 'pkg-config')
if not tmc_dep.found()
    tmc_dep = cc.find_library('tmc', required: false)
endif
if tmc_dep.found() and cc.has_header('tmc/isol.h', dependencies: tmc_dep)
    extra_ldflags += '-lrt'
else
    subdir_done()
endif

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='l2fwd_tmc'

link_whole_libs = []
if get_option('default_library') == 'static'
    link_whole_libs = dpdk_static_libraries + dpdk_drivers
endif

cnxk_test_dep_objs += tmc_dep
# Create the test executable
l2fwd_tmc_test=executable(
    test_exec,
    files('main.c', 'l2fwd_common.c', 'l2fwd_event.c', 'l2fwd_event_generic.c',
          'l2fwd_event_internal_port.c', 'l2fwd_poll.c'),
    link_whole: link_whole_libs,
    dependencies: cnxk_test_dep_objs,
    link_args: extra_ldflags,
    c_args: cflags,
    install_dir: 'bin/cnxk/l2fwd_tmc',
    install: true
)
