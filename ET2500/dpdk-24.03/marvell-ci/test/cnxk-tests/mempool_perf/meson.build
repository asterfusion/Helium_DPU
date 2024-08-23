# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

# Test script
test_script = 'cnxk_mempool_perf.sh'

# Test name
test_name = 'cnxk_mempool_perf'

# Test arguments
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'ref_numbers/cn96xx_rclk2200_sclk1100')
run_command(copy_data, 'ref_numbers/cn106xx_rclk2000_sclk1000')
run_command(copy_data, 'ref_numbers/cn106xx_rclk2500_sclk1100')

# This executable is built exactly as dpdk-test but only the custom
# mempool_perf command is available in this.
cnxk_mempool_sources = dpdk_test_sources +  files('cnxk_mempool_perf.c')

cnxk_mempool_perf_test = executable(
    'cnxk_mempool_perf',
    cnxk_mempool_sources,
    link_whole: dpdk_test_link,
    dependencies: dpdk_test_deps,
    c_args: cflags,
    include_directories: dpdk_test_inc_dir,
    install_dir: 'bin/cnxk/mempool_perf',
    install: true
)

# Add the meson test
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

# Install the sample script
install_data(
    test_script,
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/mempool_perf')
