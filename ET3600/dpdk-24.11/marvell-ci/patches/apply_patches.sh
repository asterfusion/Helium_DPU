#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.
#

set -euo pipefail

function help() {
	echo "Apply Patches."
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [PATCH_DIRS]"
}

SCRIPT_NAME="$(basename "$0")"
PATCH_DIRS="$@"
PROJECT_ROOT=${PROJECT_ROOT:-$PWD}

if [[ -z $PATCH_DIRS ]]; then
	echo "No patches to apply !"
	help
	exit 0
fi

cd ${PROJECT_ROOT}
if [[ ! -d marvell-ci/patches ]]; then
	echo "Run the script from dpdk root directory or set PROJECT_ROOT env var !!"
	exit 1
fi

for DIR in $PATCH_DIRS; do
	DIR=$PWD/marvell-ci/patches/$DIR
	if [[ -d $DIR ]]; then
		git apply $DIR/*.patch
	else
		echo "$DIR Missing !!!"
	fi
done
