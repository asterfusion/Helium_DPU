# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021, Marvell

# env files
env_files = [
        'lbk.env',
        'pktgen.env',
        'common.env',
]

foreach env : env_files
    run_command(copy_data, env)
    install_data(
        env,
        install_mode : 'rw-r--r--',
        install_dir : 'bin/cnxk/common/testpmd')
endforeach

