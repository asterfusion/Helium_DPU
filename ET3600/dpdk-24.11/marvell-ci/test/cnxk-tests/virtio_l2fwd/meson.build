# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2025 Marvell.

# Test name
test_name = 'cnxk_virtio_l2fwd'

# Test directory name relative to build directory.
test_dir = meson.current_build_dir()

# Test executable
test_exec='cnxk_virtio_l2fwd'

if meson.is_cross_build()
        soc_type = meson.get_cross_property('platform', '')
else
        soc_type = platform
endif

# Create the test executable
virtio_l2fwd_test=executable(
    test_exec,
    files('virtio_l2fwd.c', 'l2_eth_rx.c', 'l2_eth_tx.c', 'l2_emdev_deq.c', 'l2_emdev_enq.c'),
    link_whole: link_libs,
    include_directories: includes,
    dependencies: [cnxk_test_dep_objs, get_variable(def_lib + '_rte_raw_cnxk_emdev')],
    c_args: cflags,
    install_dir: '',
    install: false
)
