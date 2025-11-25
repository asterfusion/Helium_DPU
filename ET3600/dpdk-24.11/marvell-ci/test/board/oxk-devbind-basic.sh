#! /bin/sh

# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

HELP="usage: oxk-devbind-basic.sh [OPTIONS] devices..
Script for binding/unbinding devices from Linux kernel drivers.
NOTE: Options -b and -u are exclusive.
	OPTIONS:
		-b driver - Bind given devices to a given driver
		-u        - Unbind devices from their driver
	devices: Space separated List of DBDF addresses (i.e. 0001:02:00.1)"

OPTS=$(getopt -u -n $0 -o "b:uh" -- $@)

driver=""
unbind=0

eval set -- "$OPTS"

while true; do
	case "$1" in
		-h) echo $HELP; exit 0 ;;
		-b) driver=$2; shift 2 ;;
		-u) unbind=1; shift ;;
		--) shift; break ;;
		*) echo "Unknown arguments"; echo $HELP; exit 1 ;;
	esac
done

if [ "x$driver" != "x" -a $unbind -eq 1 ]; then
	echo "Cannot have -b and -u"
	echo "$HELP"
	exit 1
fi

if [ "x$driver" = "x" -a $unbind -eq 0 ]; then
	echo "Please specify either -b or -u"
	echo "$HELP"
	exit 1
fi

for dbdf in $@; do
	ddir="/sys/bus/pci/devices/$dbdf"
	cur_drv="$(readlink -n $ddir/driver)"
	if [ ! -z "$cur_drv" ]; then
		cur_drv="$(basename $cur_drv)"
	fi
	# If user wants to bind and same driver is bound, skip the device
	if [ $unbind -eq 0 -a "x$driver" = "x$cur_drv" ]; then
		continue
	fi
	# Either user wanted to unbind or we have to unbind for re-binding
	if [ -e $ddir/driver/unbind ]; then
		echo $dbdf > "$ddir/driver/unbind"
	fi
	# If user specified -b then do try to bind
	if [ "x$driver" != "x" ]; then
		echo $driver > "$ddir/driver_override"
		echo $dbdf > /sys/bus/pci/drivers_probe
	fi
done
