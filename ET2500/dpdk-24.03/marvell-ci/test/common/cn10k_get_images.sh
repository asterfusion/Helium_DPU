#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2020 Marvell.

# Script syntax:
# ... copy_asim_ref_images.sh
#
# Environment variables
# ASIM_REF_REMOTE - Remote ASIM reference image machine
# ASIM_REF_REMOTE_IMAGES - Remote ASIM reference image directory
# ASIM_TARGET_IMAGES -  Local ASIM reference image directory
#
# Script will:
# 1. Copy the reference static images to local machine
#

set -euo pipefail
shopt -s extglob

SYNC_COPY=${SYNC_COPY:-"rsync -azzh"}
ASIM_REF_REMOTE=${ASIM_REF_REMOTE:-ci@10.28.34.13}
ASIM_REF_REMOTE_IMAGES=${ASIM_REF_REMOTE_IMAGES:-/home/ci/asim_target_images}

$SYNC_COPY $ASIM_REF_REMOTE:$ASIM_REF_REMOTE_IMAGES/Image \
	$ASIM_TARGET_IMAGES/Image
$SYNC_COPY $ASIM_REF_REMOTE:$ASIM_REF_REMOTE_IMAGES/flash-cn10ka.img \
	$ASIM_TARGET_IMAGES/flash-cn10ka.img
$SYNC_COPY $ASIM_REF_REMOTE:$ASIM_REF_REMOTE_IMAGES/flash-cnf10ka.img \
	$ASIM_TARGET_IMAGES/flash-cnf10ka.img
$SYNC_COPY $ASIM_REF_REMOTE:$ASIM_REF_REMOTE_IMAGES/flash-cnf10kb.img \
	$ASIM_TARGET_IMAGES/flash-cnf10kb.img
$SYNC_COPY $ASIM_REF_REMOTE:$ASIM_REF_REMOTE_IMAGES/rootfs.tar \
	$ASIM_TARGET_IMAGES/rootfs.tar
$SYNC_COPY $ASIM_REF_REMOTE:$ASIM_REF_REMOTE_IMAGES/scp_bl0.exe-cn10xx \
	$ASIM_TARGET_IMAGES/scp_bl0.exe-cn10xx
