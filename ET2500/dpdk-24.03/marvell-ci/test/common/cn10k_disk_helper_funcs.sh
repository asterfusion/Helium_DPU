#!/bin/bash

# Copyright(C) 2021 Marvell.
# SPDX-License-Identifier: BSD-3-Clause

# Functions required to create cn10k disk image.

function cleanup_mount_point()
{
	local retry
	local backfile
	local loopdevs=$($REMOTE find /dev -name loop* | grep -v control)
	local loopdevdir
	local status=0

	# Some of the mount commands can throw a non-zero exit status even
	# after it does the desired operations.
	set +e
	trap - ERR

	for loopdev in $loopdevs; do
		loopdev=$(basename $loopdev | grep -o 'loop[0-9]*')
		backfile=$($REMOTE sudo losetup -n -l -O BACK-FILE /dev/$loopdev | awk '{print $1}' | grep asim)
		# Check whether this loop device has an asim disk backing file
		if [[ -z $backfile ]]; then
			continue
		fi

		status=1
		retry=5
		loopdevdir=$($REMOTE sudo mount | grep ${loopdev}p | tail -n1 | awk '{print $3}')
		echo "Cleaning up $loopdev with backing file $backfile and mount directory $loopdevdir"
		while [[ $status -ne 0 ]] && [[ $retry -ne 0 ]]; do
			# Unmount
			$REMOTE sudo umount $loopdevdir || true
			# Remove dev mappings
			$REMOTE sudo dmsetup remove /dev/mapper/${loopdev}p1 || true
			$REMOTE sudo dmsetup remove /dev/mapper/${loopdev}p2 || true
			$REMOTE sudo dmsetup remove /dev/mapper/${loopdev}p3 || true
			$REMOTE sudo kpartx -dv $backfile || true
			sleep 0.5
			# Detach loop device
			$REMOTE sudo losetup -d /dev/${loopdev} || true
			sleep 0.5
			# Ensure that the loop device has been detached
			backfile=$($REMOTE sudo losetup -n -l -O BACK-FILE /dev/$loopdev | awk '{print $1}' | grep asim)
			if [[ -z $backfile ]]; then
				status=0
			fi
			retry=$((retry-1))
		done
		if [[ $status -ne 0 ]]; then
			break
		fi
	done

	set -e
	trap "sig_handler ERR no" ERR
	return $status
}

function create_dataplane_disk_image()
{
	local rand_str

	if [[ -z $ASIM_TARGET_IMAGES ]]; then
		rand_str=$(head -c 64 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n1)
		# When we run two or more ASIM instances on a host machine, images needs
		# to have different paths. Otherwise the loop devices will get shared
		# between the instances.
		ASIM_TARGET_IMAGES="${REMOTE_DIR}/asim_images_${rand_str}"
	fi

	$REMOTE mkdir -p $ASIM_TARGET_IMAGES

	#  Sync pre-built images
	echo "Fetching pre-built images"
	$REMOTE ASIM_REF_REMOTE=$ASIM_REF_REMOTE \
		ASIM_REF_REMOTE_IMAGES=$ASIM_REF_REMOTE_IMAGES \
		ASIM_TARGET_IMAGES=$ASIM_TARGET_IMAGES \
		$REMOTE_DIR/marvell-ci/test/common/cn10k_get_images.sh

	echo "Building disk image"
	# Build the disk image
	$REMOTE "sudo ASIM_TARGET_IMAGES=$ASIM_TARGET_IMAGES \
		SFDISK_FILE=$REMOTE_DIR/marvell-ci/test/common/cn10k-dataplane-disk.sfdisk \
		bash $REMOTE_DIR/marvell-ci/test/common/cn10k_image_creator.sh \
		$REMOTE_DIR/build/*"
}
