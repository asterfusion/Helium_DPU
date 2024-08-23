# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

# Test name
test_name = 'udp4_recv_graph_tests'

# Arguments to the test scripts
test_args = ''

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='udp4_recv_graph'

# Create the test executable
extbuf_test=executable(
    test_exec,
    files('main.c'),
    link_whole: link_libs,
    dependencies: cnxk_test_dep_objs,
    c_args: cflags,
    install_dir: 'bin/cnxk/udp4-recv',
    install: true
)
