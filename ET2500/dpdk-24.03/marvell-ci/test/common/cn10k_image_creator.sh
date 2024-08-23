#!/bin/bash -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2020 Marvell.

# Script syntax:
# cn10k_image_creator.sh DIR1 DIR2 ... DIRN
#
# environment variables:
# ASIM_TARGET_IMAGES : Points to a directory which has the rootfs.tar, Linux Image
#		       and will also contain the output 'cn10k-dataplane-disk.img'
#		       mmc image.
#
# Script will:
#	Create 'cn10k-dataplane-disk.img' mmc image at ASIM_TARGET_IMAGES.
#	The mmc image will contain three partitions p1, p2 and p3. p1 will hold
#	the Linux kernel image, p2 will contain the rootfs and p3 will hold the
#	directories passed to the script as command line arguments.
#

trap 'cleanup $0 $LINENO $BASH_COMMAND' ERR

function help() {
	echo "Script used to create or update cn10k-dataplane-disk.img MMC image."
	echo "Environment variable ASIM_TARGET_IMAGES needs to be set to a path containing"
	echo "the Linux kernel image and rootfs.tar."
	echo ""
	echo "Usage: "
	echo "cn10k_image_creator.sh DIR1 DIR2 ... DIRn"
	echo "The script creates the MMC image with three partitions p1, p2 and p3."
	echo "p1 : will hold the Linux kernel image"
	echo "p2 : will contain the rootfs"
	echo "p3 : will hold the DIRx passed to the script as command line arguments."
}

function try_kpartx() {
	local cmd=$1
	local image=$2
	local retry
	local loop_dev
	local loop_dev_count

	# When two processes are trying to setup ASIM images simultaneously,
	# then kpartx may throw some harmless errors. Do some retries before
	# calling it a fail.
	retry=0
	while [[ 1 ]]; do
		sudo kpartx -dv $image || true

		if [[ $cmd == add ]]; then
			sudo kpartx -av $image || true
		fi

		loop_dev=`sudo losetup -a | grep -w $(realpath $image) | awk -F'[/:]' '{print $3}'`
		loop_dev_count=`echo $loop_dev | wc -w`

		# Check whether all loop devices are detached
		if [[ $cmd == del ]] && [[ $loop_dev_count -eq 0 ]]; then
			return 0
		fi

		# Check that exactly one loop device exist
		if [[ $cmd == add ]] && [[ $loop_dev_count -eq 1 ]]; then
			KERNEL_LDEV=${loop_dev}p1
			RFS_LDEV=${loop_dev}p2
			DP_LDEV=${loop_dev}p3
			return 0
		fi

		# Call device mapper remove
		for i in $loop_dev; do
			sudo dmsetup remove /dev/mapper/${i}{p1,p2,p3} || true
			sudo losetup -d /dev/$i
		done

		retry=$((retry + 1))
		if [[ $retry -le 10 ]]; then
			echo "Retrying kpartx ..."
			sleep 1
			continue
		fi
		break
	done

	echo "kpartx failed !"
	return 1
}

UPDATE=1
P3_DIR=""
while [[ "$#" -gt 0 ]]; do
	case $1 in
	-h) help; exit 0 ;;
	--skip-update) UPDATE=0 ;;
	*) P3_DIR+=$1; P3_DIR+=' ' ;;
	esac
	shift
done

if [[ -z "$ASIM_TARGET_IMAGES" ]]; then
	echo "Please set ASIM_TARGET_IMAGES environment variable"
	exit 1
fi

if [[ ! -f $ASIM_TARGET_IMAGES/Image ]]; then
	echo "Linux kernel image not found in $ASIM_TARGET_IMAGES"
	exit 1
fi

if [[ ! -f $ASIM_TARGET_IMAGES/rootfs.tar ]]; then
	echo "rootfs.tar not found in $ASIM_TARGET_IMAGES"
	exit 1
fi

IMAGE=$ASIM_TARGET_IMAGES/cn10k-dataplane-disk.img
MOUNT_PATH=$ASIM_TARGET_IMAGES/asim_mount
RSYNC_CMD="sudo rsync -azzh --delete -r"
RSYNC_COPY_CMD="sudo rsync -azzh -r --exclude .deps --exclude .libs"
SFDISK_FILE=${SFDISK_FILE:-"platform/cn10k/asim/cn10k-dataplane-disk.sfdisk"}
function cleanup()
{
	echo "Error: executing $1 at line $2: ${@:3}"
	echo
	if [[ -d $ASIM_TARGET_IMAGES/asim_mount ]]; then
		mountpoint -q $ASIM_TARGET_IMAGES/asim_mount
		if [[ $? -eq 0 ]]; then
			sudo umount $ASIM_TARGET_IMAGES/asim_mount
		fi
	fi

	if [[ -f $IMAGE ]]; then
		try_kpartx del $IMAGE
	fi
	exit 1
}

if [[ ! -f $IMAGE ]]; then
	dd if=/dev/zero of=$IMAGE count=46 bs=128M
	sfdisk $IMAGE < $SFDISK_FILE
	if [[ -f $ASIM_TARGET_IMAGES/image.cksum ]]; then
		sudo rm $ASIM_TARGET_IMAGES/image.cksum
	fi

	if [[ -f $ASIM_TARGET_IMAGES/rootfs.cksum ]]; then
		sudo rm $ASIM_TARGET_IMAGES/rootfs.cksum
	fi
	NEW_IMAGE=1
	UPDATE=1
else
	try_kpartx del $IMAGE
	NEW_IMAGE=0
fi

try_kpartx add $IMAGE
if [[ $? -ne 0 ]]; then
	echo "Failed to create loop devices"
	exit 1
fi

if [[ $NEW_IMAGE -eq 1 ]]; then
	sudo mkfs.ext4 -q /dev/mapper/$KERNEL_LDEV
	sudo mkfs.ext4 -q /dev/mapper/$RFS_LDEV
	sudo mkfs.ext4 -q /dev/mapper/$DP_LDEV
fi

if [[ ! -d $MOUNT_PATH ]]; then
	mkdir $MOUNT_PATH
fi

if [[ $UPDATE -eq 1 ]];then
	CUR_KERN_SUM=$(md5sum $ASIM_TARGET_IMAGES/Image | awk -F ' ' '{print $1}')
	CUR_RFS_SUM=$(md5sum $ASIM_TARGET_IMAGES/rootfs.tar | awk -F ' ' '{print $1}')

	sudo bash -c "echo Kernel Image Checksum: $CUR_KERN_SUM"
	sudo bash -c "echo RootFS Image Checksum: $CUR_RFS_SUM"

	KERN_SUM=
	RFS_SUM=
	if [[ -f $ASIM_TARGET_IMAGES/image.cksum ]]; then
		KERN_SUM=$(head -n 1 $ASIM_TARGET_IMAGES/image.cksum)
	fi

	if [[ -f $ASIM_TARGET_IMAGES/rootfs.cksum ]]; then
		RFS_SUM=$(head -n 1 $ASIM_TARGET_IMAGES/rootfs.cksum)
	fi

	sudo bash -c "echo $CUR_KERN_SUM > $ASIM_TARGET_IMAGES/image.cksum"
	sudo bash -c "echo $CUR_RFS_SUM > $ASIM_TARGET_IMAGES/rootfs.cksum"

	if [[ $KERN_SUM != $CUR_KERN_SUM ]]; then
		KERN_IMG_SZ=$(sudo du -h $ASIM_TARGET_IMAGES/Image | awk '{print $1}')
		echo ""
		echo "Cksum mismatch Updating kernel Image..."
		sudo mount /dev/mapper/$KERNEL_LDEV $MOUNT_PATH
		sudo bash -c "echo Kernel Image Size: $KERN_IMG_SZ"
		$RSYNC_CMD $(readlink -f $ASIM_TARGET_IMAGES/Image) $MOUNT_PATH/Image
		sudo umount $MOUNT_PATH
	fi

	if [[ $RFS_SUM != $CUR_RFS_SUM ]]; then
		echo ""
		echo "Cksum mismatch Updating RFS..."
		if [[ ! -d $ASIM_TARGET_IMAGES/tmp_rfs ]]; then
			mkdir $ASIM_TARGET_IMAGES/tmp_rfs
		fi
		sudo mount /dev/mapper/$RFS_LDEV $MOUNT_PATH
		sudo tar -xf $ASIM_TARGET_IMAGES/rootfs.tar --directory $ASIM_TARGET_IMAGES/tmp_rfs
		ROOTFS_SZ=$(sudo du -sh $ASIM_TARGET_IMAGES/tmp_rfs/ | awk '{print $1}')
		sudo bash -c "echo RootFS Size: $ROOTFS_SZ"
		$RSYNC_CMD $ASIM_TARGET_IMAGES/tmp_rfs/* $MOUNT_PATH
		sudo rm -rf $ASIM_TARGET_IMAGES/tmp_rfs
		sudo umount $MOUNT_PATH
	fi
fi

sudo mount /dev/mapper/$DP_LDEV $MOUNT_PATH
for ARG_PATH in $P3_DIR
do
	echo "Syncing $ARG_PATH to /dev/mapper/$DP_LDEV..."
	if [[ -e $ARG_PATH ]]; then
		ARG_PATH_SZ=$(sudo du -sh $ARG_PATH | awk '{print $1}')
		sudo bash -c "echo Path ${ARG_PATH} Sync Size: $ARG_PATH_SZ"
		$RSYNC_COPY_CMD $ARG_PATH $MOUNT_PATH/
	else
		echo "Invalid path: $ARG_PATH"
	fi
done
sudo umount $MOUNT_PATH

rmdir $MOUNT_PATH
try_kpartx del $IMAGE
sudo chmod 666 $IMAGE
