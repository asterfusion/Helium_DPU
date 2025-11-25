# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

# Test name
test_name = 'cnxk_hwpool_tests'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cnxk-hwpool'

# Create the test executable
extbuf_test=executable(
    test_exec,
    files('hwpool.c'),
    link_whole: link_libs,
    dependencies:[cnxk_test_dep_objs, get_variable(def_lib + '_rte_mempool_cnxk')],
    c_args: cflags,
    install_dir: 'bin/cnxk/hwpool',
    install: true
)

# Add the meson test
test(
    test_name,
    extbuf_test,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    is_parallel : false,
    suite : 'cnxk-tests')

