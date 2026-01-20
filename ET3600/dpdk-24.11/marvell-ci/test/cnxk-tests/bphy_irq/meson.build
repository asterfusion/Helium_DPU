# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

# Test name
test_name = 'bphy_irq_tests'

# Test script
test_script = 'bphy_irq.sh'

# Arguments to the test scripts
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='bphy-irq'

# Copy the required scripts to build directory.
run_command(copy_data, test_script)

# Create the test executable
bphy_irq_test=executable(
    test_exec,
    files('bphy_irq.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: 'bin/cnxk/bphy_irq',
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
    'bphy_irq.sh',
    install_mode : 'rwxr-xr-x',
    install_dir : 'bin/cnxk/bphy_irq')
