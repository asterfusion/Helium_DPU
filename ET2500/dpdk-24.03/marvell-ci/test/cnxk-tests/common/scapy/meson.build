# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2021, Marvell

# scapy scripts
scapy_scripts = [
        'sendrecv.py',
        'createpcap.py',
]

foreach script : scapy_scripts
    run_command(copy_data, script)
    install_data(
        script,
        install_mode : 'rwxr-xr-x',
        install_dir : 'bin/cnxk/common/scapy')
endforeach

