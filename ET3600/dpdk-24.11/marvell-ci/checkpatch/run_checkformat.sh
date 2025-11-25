#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
cd $PROJECT_ROOT
git format-patch -n1 -s -q
./marvell-ci/checkpatch/checkformat.sh 0001*
