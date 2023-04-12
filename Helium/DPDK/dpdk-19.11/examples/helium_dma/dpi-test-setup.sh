#Copyright (c) 2020 Marvell.
#SPDX-License-Identifier: BSD-3-Clause

#set this to 2, to use 2 DPI blocks when exists (like, on 98xx
NUM_DPI=1

# Enable DPI VFs
NUMVFS=8
DPIPF=$(lspci -d 177d:a080|awk '{print $1}' | head -${NUM_DPI})
echo "###### DPI PFs ######"
echo "$DPIPF"

mkdir -p /dev/huge
mount -t hugetlbfs nodev /dev/huge
echo 12 > /sys/kernel/mm/hugepages/hugepages-524288kB/nr_hugepages

echo -e "\n"
echo "Creating DPI VFs ..."
for PF in $DPIPF
do
	DPIVFS=$(cat /sys/bus/pci/devices/$PF/sriov_numvfs)
	echo "Current number of VFs under DPIPF $PF = $DPIVFS"
	if [ x"$DPIVFS" != x"$NUMVFS" ]; then
		echo "Creating $NUMVFS VFs for DPIPF $PF ..."
		echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs
		echo $NUMVFS > /sys/bus/pci/devices/$PF/sriov_numvfs
		if [ x"$?" != "x0" ]; then
			echo -n \
	"""Failed to enable $DPI DMA queues.
	""" >&2
		exit 1
	fi
	fi
done

# bind only required NPA and DPI VFs to vfio-pci
DPIVF=$(lspci -d 177d:a081|awk '{print $1}')
echo -e "\n"
echo "###### DPI VFs ######"
echo "$DPIVF"

NPAPF=$(lspci -d 177d:a0fb|awk '{print $1}'|head -1)
echo -e "\n"
echo "Using NPA PF $NPAPF ..."

dpi_devs=(${DPIVF} $NPAPF)

for DEV in ${dpi_devs[*]}; do
	echo $devs
	if [ -e /sys/bus/pci/devices/$DEV/driver/unbind ]; then
                drv="$(readlink -f /sys/bus/pci/devices/$DEV/driver)"
                drv="$(basename $drv)"
                if [ "$drv" != "vfio-pci" ]; then
                        echo $DEV > "/sys/bus/pci/devices/$DEV/driver/unbind"
                fi
        fi
        echo vfio-pci > "/sys/bus/pci/devices/$DEV/driver_override"
        echo $DEV > /sys/bus/pci/drivers_probe
        echo "  Device $DEV moved to VFIO-PCI"
done

