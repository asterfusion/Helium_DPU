#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

ERR=
PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
cd $PROJECT_ROOT
export DPDK_CHECKPATCH_CODESPELL=$PROJECT_ROOT/marvell-ci/checkpatch/dictionary.txt
export DPDK_CHECKPATCH_PATH=$PROJECT_ROOT/marvell-ci/checkpatch/checkpatch.pl
./devtools/check-git-log.sh -n1 || ERR=1
git format-patch -n1 -q -o patches
./devtools/checkpatches.sh patches/* || ERR=1

if [[ -n $ERR ]]; then
	echo "Checkpatch / git log check failed !!!"
	exit 1
fi

