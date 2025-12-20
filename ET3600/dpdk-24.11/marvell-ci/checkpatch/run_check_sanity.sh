#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

echo "========================"
echo "Meson Files Sanity Check"
echo "========================"
./devtools/check-meson.py > check_meson.log
cat check_meson.log
grep "^Error" check_meson.log && false

# Ignore marvell-ci config files in SPDX check
echo "=================="
echo "SPDX License Check"
echo "=================="
SPDX_ERRORS=$(./devtools/check-spdx-tag.sh | head -n -3 |
	grep -P -v "^.*\.(asim|rst|pcap|patch|sfdisk|kb|inb|outb)$" |
	grep -v marvell-ci/build/config |
	grep -v marvell-ci/checkpatch/checkpatch.conf |
	grep -v marvell-ci/checkpatch/const_structs.checkpatch |
	grep -v marvell-ci/doc/source/conf.py |
	grep -v marvell-ci/test/cnxk-tests/crypto_perf/ref_numbers |
	grep -v marvell-ci/test/cnxk-tests/event_perf/ref_numbers |
	grep -v marvell-ci/test/cnxk-tests/flow_perf/ref_numbers |
	grep -v marvell-ci/test/cnxk-tests/mempool_perf/ref_numbers |
	grep -v marvell-ci/test/cnxk-tests/fwd_perf/ref_numbers |
	grep -v marvell-ci/test/cnxk-tests/dma_perf/ref_numbers |
	grep -v .clang-format |
	grep -v marvell-ci/klocwork/kw_override.h || true
)

if [[ -n $SPDX_ERRORS ]]; then
	echo "SPDX Errors Found in Following files"
	echo $SPDX_ERRORS
	exit 1
fi

echo "================="
echo "Doc vs Code Check"
echo "================="
./devtools/check-doc-vs-code.sh HEAD~1

