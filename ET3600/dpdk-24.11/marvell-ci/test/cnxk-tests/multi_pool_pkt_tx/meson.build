# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cnxk-multi_pool_pkt_tx'

# Test install dir
test_install_dir = 'bin/cnxk/multi_pool_pkt_tx'

# Test script
test_script = 'cnxk_multi_pool_pkt_tx.sh'

# Copy the required scripts to build directory.
run_command(copy_data, test_script)

# Create the test executable
multi_pool_pkt_tx_test=executable(
    test_exec,
    files('multi_pool_pkt_tx.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: test_install_dir,
    install: true
)

# Install the script
install_data(
    test_script,
    install_mode : 'rwxr-xr-x',
    install_dir : test_install_dir)

# Add vector test
test_name = 'cnxk_multi_pool_pkt_tx'
test_args = ''
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

# Add scalar test
test_name = 'cnxk_multi_pool_pkt_tx_scalar'
test_args = '1'
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

