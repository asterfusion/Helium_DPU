# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.


# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cnxk-extbuf'

# Create the test executable
extbuf_test=executable(
    test_exec,
    files('extbuf.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: 'bin/cnxk/extbuf',
    install: true
)
# Add the meson test
test_name = 'cnxk_extbuf_tests'
test_script = 'cnxk_extbuf.sh'
test_args = ''
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')
# Copy the required scripts to build directory.
run_command(copy_data, test_script)


# Add the meson test
test_name = 'cnxk_indirectbuf_tests'
test_script = 'cnxk_indirectbuf.sh'
test_args = ''
test(
    test_name,
    cnxk_test_script_wrapper,
    env : ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args : [test_script, test_args],
    is_parallel : false,
    suite : 'cnxk-tests')
# Copy the required scripts to build directory.
run_command(copy_data, test_script)


# Install the script
install_data(
    'cnxk_extbuf.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/extbuf')
install_data(
    'cnxk_indirectbuf.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/extbuf')
