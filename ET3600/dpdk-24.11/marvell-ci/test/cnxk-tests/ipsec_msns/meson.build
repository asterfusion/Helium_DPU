# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

# Test name
test_name = 'cnxk_ipsec_msns'

# Test script
test_script = 'cnxk_ipsec_msns.sh'

# Arguments to the test scripts
test_args = '$REMOTE_DIR'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cnxk_ipsec_msns'

if meson.is_cross_build()
        soc_type = meson.get_cross_property('platform', '')
else
        soc_type = platform
endif

if soc_type == 'cn9k'
        cflags += ['-DMSNS_CN9K']
endif

# Copy the required scripts to build directory.
run_command(copy_data, test_script)

# Create the test executable
ipsec_msns_test=executable(
    test_exec,
    files('ipsec_msns.c'),
    link_whole: link_libs,
    include_directories: includes,
    dependencies: [cnxk_test_dep_objs, get_variable(def_lib + '_rte_net_cnxk')],
    c_args: cflags,
    install_dir: 'bin/cnxk/ipsec_msns',
    install: true
)

# Add the meson test
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')

# Install the script
install_data(
    'cnxk_ipsec_msns.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/ipsec_msns')
