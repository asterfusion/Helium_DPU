# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021, Marvell

if not dpdk_conf.has('RTE_PORT_PCAP')
    subdir_done()
endif

executable(
    'pcap-pkt-cnt',
    files('pcap_pkt_cnt.c'),
    dependencies: cnxk_test_dep_objs,
    install: true,
    install_dir : 'bin/cnxk/common/pcap')

executable(
    'pcap-len',
    files('pcap_len.c'),
    dependencies: cnxk_test_dep_objs,
    install: true,
    install_dir : 'bin/cnxk/common/pcap')

executable(
    'pcap-mac',
    files('pcap_mac.c'),
    dependencies: cnxk_test_dep_objs,
    install: true,
    install_dir : 'bin/cnxk/common/pcap')

run_command(copy_data, 'sample.pcap')
install_data(
    'sample.pcap',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/common/pcap')

run_command(copy_data, 'pcap.env')
install_data(
    'pcap.env',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/common/pcap')
