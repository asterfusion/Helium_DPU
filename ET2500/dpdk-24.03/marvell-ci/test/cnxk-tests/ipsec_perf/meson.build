# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.
# Test script
test_script = 'cnxk_ipsec_perf.sh'
# Test name
test_name = 'cnxk_ipsec_la_perf'
test_inline_name = 'cnxk_ipsec_inline_perf'
# Test arguments
test_args = '$REMOTE_DIR'
# Test directory name relative to build directory.
test_dir = meson.current_build_dir()
# Copy the required scripts to build directory.
run_command(copy_data, test_script)
run_command(copy_data, 'cnxk_ipsec_perf_gen.sh')
run_command(copy_data, 'ep0_lookaside_crypto.cfg')
run_command(copy_data, 'ep0_lookaside_protocol.cfg')
run_command(copy_data, 'ep0_inline_protocol_ob_sp.cfg')
run_command(copy_data, 'ep0_inline_protocol_ib_sp.cfg')
run_command(copy_data, 'ep0_inline_protocol_ob_dp.cfg')
run_command(copy_data, 'ep0_inline_protocol_ib_dp.cfg')
run_command(copy_data, 'ep0_inline_protocol_ob_aescbc.cfg')
run_command(copy_data, 'ep0_inline_protocol_ob_aesgcm.cfg')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.lc.outb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.lc.inb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.lp.outb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.lp.inb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.lp_e.outb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.lp_e.inb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.ip.outb')
run_command(copy_data, 'ref_numbers/cn9k/rclk2200_sclk1100_cptclk1000.96xx.ip.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lc.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lc.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lp.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lp.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lp_e.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lp_e.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lp_ev.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.lp_ev.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_ev.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_ev.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_ev_ss.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_ev_ss.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_p.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_p.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_p_ss.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2000_sclk1000.106xx.ip_p_ss.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lc.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lc.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lp.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lp.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lp_e.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lp_e.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lp_ev.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.lp_ev.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_ev.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_ev.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_ev_ss.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_ev_ss.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_p.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_p.inb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_p_ss.outb')
run_command(copy_data, 'ref_numbers/cn10k/rclk2500_sclk1100.106xx.ip_p_ss.inb')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_64.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_380.pcap')
run_command(copy_data, 'pcap/enc_aes-cbc_sha1-hmac_1410.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_64.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_380.pcap')
run_command(copy_data, 'pcap/enc_aes-gcm_1410.pcap')
# Add the meson test
test(test_name,
    cnxk_test_script_wrapper,
    env : [['DPDK_TEST=' + test_name],
    ['TEST_DIR=' + test_dir]],
    args : [[test_script], [test_args]],
    is_parallel : false, suite : 'cnxk-tests')

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
             install_dir : 'bin/cnxk/ipsec_perf')
