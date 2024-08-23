#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

if [[ ! -f bphy-irq ]]; then
	echo "bphy-irq not found !!"
	exit 1
fi

DEV=$(lspci -d :a089 | grep -E -o "[[:digit:]]{2}:[[:digit:]]{2}\.[[:digit:]]{1}")
[ -z "$DEV" ] && exit 0
./bphy-irq "$DEV"
