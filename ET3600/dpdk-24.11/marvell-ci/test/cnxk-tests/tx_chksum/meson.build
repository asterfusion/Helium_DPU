# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

# Test script
test_script = 'cnxk_tx_chksum.sh'

# Test name
test_name = 'cnxk_tx_chksum'
test_mseg_name = 'cnxk_mseg_tx_chksum'

# Test arguments
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'in.pcap')
run_command(copy_data, 'out.pcap')
run_command(copy_data, 'in_mseg.pcap')
run_command(copy_data, 'out_mseg.pcap')

# Add the meson test
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

# Add mseg
test_args+= '  --mseg'
test(
    test_mseg_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_mseg_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

# Install the sample script
install_data(
    test_script,
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/tx_chksum')
