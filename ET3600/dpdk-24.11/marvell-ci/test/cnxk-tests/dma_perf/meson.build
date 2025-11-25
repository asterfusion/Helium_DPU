# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.
# Test script
test_script = 'cnxk_dma_perf.sh'
# Test name
test_name = 'cnxk_dma_perf'
# Test arguments
test_args = '$REMOTE_DIR'
# Test directory name relative to build directory.
test_dir = meson.current_build_dir()
# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'mem_to_mem_config.ini')
run_command(copy_data, 'mem_to_dev_config.ini')
run_command(copy_data, 'dev_to_mem_config.ini')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1100.cn96.m2m')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1100.cn96.m2d')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1100.cn96.d2m')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn106.m2m')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn106.m2d')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn106.d2m')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn106.m2m')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn106.m2d')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn106.d2m')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn106.m2m')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn106.m2d')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn106.d2m')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn106.m2m')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn106.m2d')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn106.d2m')
# Add the meson test
test(test_name,
    cnxk_test_script_wrapper,
    env : [['DPDK_TEST=' + test_name],
    ['TEST_DIR=' + test_dir]],
    args : [[test_script], [test_args]],
    is_parallel : false, suite : 'cnxk-tests')
# Install the sample script
install_data(test_script,
             install_mode : 'rwxr-xr-x',
             install_dir : 'bin/cnxk/dma_perf')
