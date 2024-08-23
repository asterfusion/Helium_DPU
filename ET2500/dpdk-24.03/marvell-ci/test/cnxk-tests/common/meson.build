# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021, Marvell

if not get_option('tests')
    subdir_done()
endif

# This executable is used as a workaround to make sure that the exe_wrapper gets
# called for scripts also. In the exe_wrapper, this executable is ignored. Note
# that the cnxk_test_dep_objs is inherited from app/test/meson.build.
cnxk_test_script_wrapper = executable(
    'cnxk-test-script-wrapper',
    files('cnxk_test_script_wrapper.c'),
    dependencies: cnxk_test_dep_objs,
    install: false)

# Helper command to copy files to build dir
copy_data = find_program('copy_data.py')

# These sources/dependencies/includes can be used by a cnxk specific test
# to build a lean dpdk-test like binary with its own custom command.
dpdk_test_sources = files('../../../../app/test/test.c')
dpdk_test_sources += files('../../../../app/test/commands.c')
dpdk_test_sources += files('../../../../app/test/test_pmd_perf.c')
dpdk_test_sources += files('../../../../app/test/packet_burst_generator.c')
dpdk_test_sources += files('../../../../app/test/test_timer_secondary.c')
dpdk_test_sources += files('../../../../app/test/test_mp_secondary.c')
dpdk_test_sources += files('../../../../app/test/test_pdump.c')
dpdk_test_sources += files('../../../../app/test/sample_packet_forward.c')
dpdk_test_inc_dir = include_directories('../../../../app/test')
dpdk_test_link = dpdk_static_libraries + dpdk_drivers
dpdk_test_deps = cnxk_test_dep_objs + ext_deps

subdir('scapy')
subdir('pcap')
subdir('testpmd')
subdir('remote')
