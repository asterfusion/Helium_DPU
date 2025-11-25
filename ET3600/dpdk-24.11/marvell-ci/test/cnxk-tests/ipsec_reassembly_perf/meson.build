# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.
# Test script
test_script = 'cnxk_ipsec_reassembly_perf.sh'
# Test name
test_name = 'cnxk_ipsec_reassembly_perf'
# Test arguments
test_args = '$REMOTE_DIR'
# Test directory name relative to build directory.
test_dir = meson.current_build_dir()
# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'ep0_inline_protocol_ib_reassembly.cfg')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_ev.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_ev_ss.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_p.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_p_ss.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_ev.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_ev_ss.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_p.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_p_ss.inb')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_64_1.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_64_2.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_64_3.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_64_4.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_380_1.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_380_2.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_380_3.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_1410_1.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_1410_2.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_reas_1410_3.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_64_1.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_64_2.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_64_3.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_64_4.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_380_1.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_380_2.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_380_3.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_1410_1.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_1410_2.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_reas_1410_3.pcap')
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
             install_dir : 'bin/cnxk/ipsec_reassembly_perf')
