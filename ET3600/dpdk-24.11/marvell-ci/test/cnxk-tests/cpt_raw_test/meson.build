# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2024 Marvell.
#

sources = files( 'main.c')

# Test name
test_name = 'cpt_raw_test'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cpt_raw_test'

# Create the test executable
raw_test=executable(
    test_exec,
    sources,
    link_whole: link_libs,
    dependencies:[ext_deps, get_variable(def_lib + '_rte_crypto_cnxk')],
    c_args: cflags,
    install_dir: 'bin/cnxk/crypto',
    install: true
)

# Add the meson test
test(
    test_name,
    raw_test,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    is_parallel : false,
    suite : 'cnxk-tests')