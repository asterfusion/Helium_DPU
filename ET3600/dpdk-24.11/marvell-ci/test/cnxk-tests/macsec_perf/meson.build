# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

# Test script
test_script = 'cnxk_macsec_perf.sh'
# Test name
test_inline_name = 'cnxk_macsec_inline_perf'
# Test arguments
test_args = '$REMOTE_DIR'
# Test directory name relative to build directory.
test_dir = meson.current_build_dir()
# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'cnxk_macsec_perf_gen.sh')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.103xx.ip.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.103xx.ip.inb')
run_command(copy_data, 'pcap/port_0_enc_pkt_64B.pcap')
run_command(copy_data, 'pcap/port_0_enc_pkt_380B.pcap')
run_command(copy_data, 'pcap/port_0_enc_pkt_1410B.pcap')
run_command(copy_data, 'pcap/port_0_plain_pkt_64B.pcap')
run_command(copy_data, 'pcap/port_0_plain_pkt_380B.pcap')
run_command(copy_data, 'pcap/port_0_plain_pkt_1410B.pcap')
run_command(copy_data, 'pcap/port_1_enc_pkt_64B.pcap')
run_command(copy_data, 'pcap/port_1_enc_pkt_380B.pcap')
run_command(copy_data, 'pcap/port_1_enc_pkt_1410B.pcap')
run_command(copy_data, 'pcap/port_1_plain_pkt_64B.pcap')
run_command(copy_data, 'pcap/port_1_plain_pkt_380B.pcap')
run_command(copy_data, 'pcap/port_1_plain_pkt_1410B.pcap')
# Add the meson test
test_args+= ' inline'
test(test_inline_name,
    cnxk_test_script_wrapper,
    env : [['DPDK_TEST=' + test_inline_name],
    ['TEST_DIR=' + test_dir]],
    args : [[test_script], [test_args]],
    is_parallel : false, suite : 'cnxk-tests')
# Install the sample script
install_data(test_script,
             install_mode : 'rwxr-xr-x',
             install_dir : 'bin/cnxk/macsec_perf')
