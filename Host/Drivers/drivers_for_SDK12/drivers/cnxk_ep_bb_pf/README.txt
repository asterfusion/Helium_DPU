# Introduction

The Physical Function (PF) Baseband Device (BBDEV) driver provides a means to
create VFs for use by bbdev PMD.

## Usage
To load the driver
# insmod cnxk_ep_bb_pf.ko

To create VFs
# echo <num_vfs> > /sys/bus/pci/devices/<Pci addr of BBdev PF>/sriov_numvfs

To delete VFs
# echo 0 > /sys/bus/pci/devices/<Pci addr of BBdev PF>/sriov_numvfs

To unload the driver
# rmmod cnxk_ep_bb_pf
