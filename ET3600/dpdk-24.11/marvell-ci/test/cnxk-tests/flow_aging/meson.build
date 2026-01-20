# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

# Test script
test_script = 'cnxk_flow_aging.sh'

# Test name
test_name = 'flow_aging'

# Test arguments
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'pcap/eth_vlan_ipv4_tcp.pcap')
run_command(copy_data, 'pcap/eth_vlan_ipv4_ipv6_tcp_2flows.pcap')

# Add the meson test
test(test_name,
     cnxk_test_script_wrapper,
     env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
     args : [test_script, test_args],
     is_parallel : false,
     suite : 'cnxk-tests')

# Install the sample script
install_data(test_script,
             install_mode : 'rwxr-xr-x',
             install_dir : 'bin/cnxk/flow_aging')
