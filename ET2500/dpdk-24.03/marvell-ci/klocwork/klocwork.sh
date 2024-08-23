#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.
#

set -euo pipefail

function help() {
	set +x
	echo "Klocwork Check"
	echo ""
	echo "Usage:"
	echo "$SCRIPT_NAME [ARGUMENTS]..."
	echo ""
	echo "Mandatory Arguments"
	echo "==================="
	echo "--build-root | -r            : Build root directory"
	echo ""
	echo "Optional Arguments"
	echo "==================="
	echo "--jobs | -j                  : Number of parallel jobs [Default: 4]"
	echo "--project-root | -p          : DPDK Project root [Default: PWD]"
	echo "--help | -h                  : Print this help and exit"
	set -x
}

SCRIPT_NAME="$(basename "$0")"
if ! OPTS=$(getopt \
	-o "r:j:p:h" \
	-l "build-root:,jobs:,project-root:,help" \
	-n "$SCRIPT_NAME" \
	-- "$@"); then
	help
	exit 1
fi

BUILD_ROOT=
MAKE_J=4
PROJECT_ROOT="$PWD"

eval set -- "$OPTS"
unset OPTS
while [[ $# -gt 1 ]]; do
	case $1 in
		-r|--build-root) shift; BUILD_ROOT=$1;;
		-j|--jobs) shift; MAKE_J=$1;;
		-p|--project-root) shift; PROJECT_ROOT=$1;;
		-h|--help) help; exit 0;;
		*) help; exit 1;;
	esac
	shift
done


if [[ -z $BUILD_ROOT ]]; then
	echo "Build root directory arg should be set !!"
	help
	exit 1
fi

PROJECT_ROOT=$(realpath $PROJECT_ROOT)
mkdir -p $BUILD_ROOT
BUILD_ROOT=$(realpath $BUILD_ROOT)
BUILD_DIR=$BUILD_ROOT/build

rm -rf $BUILD_DIR

cd $PROJECT_ROOT

CROSS_FILE=$PROJECT_ROOT/marvell-ci/build/config/arm64_cn10k_linux_gcc-marvell

meson $BUILD_DIR --cross-file $CROSS_FILE

rm -rf .kwlp .kwps
kwcheck create
kwcheck set license.host=llic5-02.marvell.com license.port=33138

# List of directories to ignore in klocwork checks
IGNORE_FILES=""
for dir in common crypto event mempool net; do
	DIRS=$(find drivers/${dir}/* -maxdepth 0 -name '*' -type d | \
		grep -v cnxk | sed 's/^/*/1' | sed 's/$/\/*/g' | \
		awk '{printf  "%s,", $1}')
	IGNORE_FILES="${IGNORE_FILES}${DIRS}"
done
IGNORE_FILES="${IGNORE_FILES},*/lib/*,*/app/*,*/examples/*,*/usertools/*,\
*/devtools/*,*/buildtools/*,*/kernel/*,*/drivers/baseband/*,*/drivers/bus/*,\
*/drivers/compress/*,*/drivers/raw/*,*/drivers/regex/*,*/drivers/vdpa/*"

kwinject --ignore-files $IGNORE_FILES -w --white-dir $BUILD_DIR \
	ninja -C $BUILD_DIR -j $MAKE_J -v
kwcheck import ${PROJECT_ROOT}/marvell-ci/klocwork/kw_override.h
kwcheck import -t kb ${PROJECT_ROOT}/marvell-ci/klocwork/local.kb
kwcheck run -r -b kwinject.out -F detailed --report kwreport-detailed.txt
kwcheck list -F scriptable --report kwreport-scritpable.txt

CNXK_ISSUES=$(wc -l kwreport-scritpable.txt | awk '{print $1}')

echo "#########################################################################"
echo "Klocwork CNXK Issues: $CNXK_ISSUES"
echo "Klocwork Report : $PWD/kwreport-detailed.txt"
echo "#########################################################################"


