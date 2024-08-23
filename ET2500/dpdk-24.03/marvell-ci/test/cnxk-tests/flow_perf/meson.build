# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

# Test script
test_script = 'cnxk_flow_perf.sh'

# Test name
test_name = 'flow_perf'

# Test arguments
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1000.96xx')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100.96xx')
run_command(copy_data, 'ref_numbers/cn9k/rclk1800_sclk1000.96xx')

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
    install_dir : 'bin/cnxk/flow_perf')
