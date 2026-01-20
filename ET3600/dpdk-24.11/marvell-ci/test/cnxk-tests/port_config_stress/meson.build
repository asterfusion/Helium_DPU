# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2025 Marvell.

# Define test script name
test_script = 'port_config_stress.sh'

# Define test name
test_name = 'port_config_stress'

# Define install directory for the test binary
test_install_dir = 'bin/cnxk/cnxk-test'

# Define test directory relative to build dir
test_dir = meson.current_build_dir()

# Copy the test script to the build directory
run_command(copy_data, test_script)

# Define the test binary
executable(
    test_name,
    files('port_config_stress.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: test_install_dir,
    install: true
)

# Register the test with Meson
test(
    test_name,
    cnxk_test_script_wrapper,
    env: ['DPDK_TEST=' + test_name, 'TEST_DIR=' + test_dir],
    args: [test_script, '$REMOTE_DIR'],
    is_parallel: false,
    suite: 'cnxk-tests'
)

# Install the test script
install_data(
    test_script,
    install_mode: 'rwxr-xr-x',
    install_dir: test_install_dir
)

