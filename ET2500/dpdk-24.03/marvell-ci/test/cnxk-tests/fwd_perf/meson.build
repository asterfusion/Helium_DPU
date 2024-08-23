# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.
# Test script
test_script = 'cnxk_fwd_perf.sh'
# Test name
test_name = 'cnxk_fwd_perf'
# Test arguments
test_args = '$REMOTE_DIR'
# Test directory name relative to build directory.
test_dir = meson.current_build_dir()
# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'cnxk_fwd_gen.sh')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1100.cn96.testpmd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1100.cn96.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1100.cn96.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn106.testpmd')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn106.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn106.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn106.testpmd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn106.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn106.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn106.testpmd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn106.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn106.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn106.testpmd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn106.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn106.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn103.testpmd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn103.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1100.cn103.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn103.testpmd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn103.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2500_sclk1000.cn103.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn103.testpmd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn103.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2200_sclk1000.cn103.l3fwd')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn103.testpmd')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn103.l2fwd')
run_command(copy_data, 'ref_numbers/rclk2000_sclk1000.cn103.l3fwd')
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
             install_dir : 'bin/cnxk/fwd_perf')
