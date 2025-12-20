# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

# Test name
test_name = 'cnxk_mbuf_perf'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec = 'mbuf-perf'

# Create the test executable
mbuf_perf_test=executable(
    test_exec,
    files('mbuf_perf.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: 'bin/cnxk/mbuf_perf',
    install: true,
)

# Add the meson test
test(
    test_name,
    mbuf_perf_test,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    is_parallel : false,
    suite : 'cnxk-tests')

