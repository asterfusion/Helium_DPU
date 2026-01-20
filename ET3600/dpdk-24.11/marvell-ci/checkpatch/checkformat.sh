#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2020 Marvell.

# Script syntax:
# checkformat.sh [FILE...]
#
# Optional environment variables:
# EXTRA_ARGS - extra arguments to pass to clang-format-diff for each file.
# CLANG_FORMAT - clang-format-diff tool to use. Some distributions have it in
#                PATH (i.e. Ubuntu), some in /usr/share (i.e. Arch Linux).
#
# Script will run clang-format-diff against every FILE passed as an argument.
# If any of the files reported errors, script will return 1.
# Output of clang-format-diff is printed for every file or "OK" is written.
EXTRA_ARGS=${EXTRA_ARGS:-""}
CLANG_FORMAT_DEF0="clang-format-diff"
CLANG_FORMAT_DEF1="/usr/share/clang/clang-format-diff.py"
CLANG_FORMAT_DEF2="clang-format-diff.py"
CLANG_FORMAT=${CLANG_FORMAT:-}
# Match cnxk-common, cn9k and cn10k files.
FORMAT_REGEX_CN="drivers/.*/cn.*/.*\.[chS]$"
# Match Odyssey files.
FORMAT_REGEX_ODY="drivers/dma/odm/.*\.[chS]$"

status=0

if [[ -n $CLANG_FORMAT ]]; then
	if [[ -z $(which $CLANG_FORMAT 2> /dev/null) ]]; then
		echo "Given CLANG_FORMAT not found. Exiting..."
		exit 1
	fi
elif [[ -n $(which $CLANG_FORMAT_DEF0 2> /dev/null) ]]; then
	CLANG_FORMAT=$CLANG_FORMAT_DEF0
elif [[ -n $(which $CLANG_FORMAT_DEF1 2> /dev/null) ]]; then
	CLANG_FORMAT=$CLANG_FORMAT_DEF1
elif [[ -n $(which $CLANG_FORMAT_DEF2 2> /dev/null) ]]; then
	CLANG_FORMAT=$CLANG_FORMAT_DEF2
else
	echo "No valid clang-format-diff found. exiting..."
	exit 1
fi

echo "Checking format using $CLANG_FORMAT..."

for f in $@; do
	printf '=%.0s' $(seq 1 ${#f})
	echo -e "\n$f"
	printf '=%.0s' $(seq 1 ${#f})
	echo ""
	output=$(cat $f | $CLANG_FORMAT -p1 -regex "${FORMAT_REGEX_CN}" $EXTRA_ARGS 2>&1)
	output+=$(cat $f | $CLANG_FORMAT -p1 -regex "${FORMAT_REGEX_ODY}" $EXTRA_ARGS 2>&1)
	# Ignore non-existing file comparisons because it means those files
	# have been removed in later commits or patch wouldn't apply.
	output=${output/No such file or directory/}
	if [ ! -z "$output" ]; then
		status=1
	else
		output="OK"
	fi
	echo "$output"
done

exit $status
