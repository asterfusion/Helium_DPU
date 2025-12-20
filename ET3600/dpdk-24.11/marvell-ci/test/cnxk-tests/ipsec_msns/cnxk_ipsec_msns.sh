#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -e

if [[ ! -f cnxk_ipsec_msns ]]; then
	echo "cnxk_ipsec_msns not found !!"
	exit 1
fi

VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
IF0=0002:02:00.0
LOG=rx.txt

rm -rf $LOG

$VFIO_DEVBIND -b vfio-pci $IF0

timeout 15 stdbuf -o 0 ./cnxk_ipsec_msns \
	-a 0002:02:00.0,custom_sa_act=1 \
	-a 0002:1d:00.0 \
	-a 0002:20:00.1 > $LOG &

echo "================================"
while [[ ! -f $LOG ]]; do
	echo "Waiting for log"
	sleep 1
	continue
done
echo "================================"

sleep 1
cat $LOG
$VFIO_DEVBIND -u $IF0

TEST0=$(grep "Test RTE_PMD_CNXK_SEC_ACTION_ALG0" $LOG | awk '{print $3}')
TEST1=$(grep "Test RTE_PMD_CNXK_SEC_ACTION_ALG1" $LOG | awk '{print $3}')
TEST2=$(grep "Test RTE_PMD_CNXK_SEC_ACTION_ALG2" $LOG | awk '{print $3}')

if [[ $TEST0 != "PASS" ]]; then
	echo "Test RTE_PMD_CNXK_SEC_ACTION_ALG0 FAILED"
	rm -rf $LOG
	exit 1
fi

if [[ $TEST1 != "PASS" ]]; then
	echo "Test RTE_PMD_CNXK_SEC_ACTION_ALG1 FAILED"
	rm -rf $LOG
	exit 1
fi

if [[ $TEST2 != "PASS" ]]; then
	echo "Test RTE_PMD_CNXK_SEC_ACTION_ALG2 FAILED"
	rm -rf $LOG
	exit 1
fi

PART_106B0=$(cat /proc/device-tree/soc\@0/chiprevision)

if [[ $PART_106B0 == "B0" ]]; then
	TEST3=$(grep "Test RTE_PMD_CNXK_SEC_ACTION_ALG3" $LOG | awk '{print $3}')
	TEST4=$(grep "Test RTE_PMD_CNXK_SEC_ACTION_ALG4" $LOG | awk '{print $3}')

	if [[ $TEST3 != "PASS" ]]; then
		echo "Test RTE_PMD_CNXK_SEC_ACTION_ALG3 FAILED"
		rm -rf $LOG
		exit 1
	fi

	if [[ $TEST4 != "PASS" ]]; then
		echo "Test RTE_PMD_CNXK_SEC_ACTION_ALG4 FAILED"
		rm -rf $LOG
		exit 1
	fi
fi

echo "CUSTOM SA ACT TEST SUCCESSFUL"

$VFIO_DEVBIND -b vfio-pci $IF0
$VFIO_DEVBIND -b vfio-pci 0002:1e:00.0
timeout 15 stdbuf -o 0 ./cnxk_ipsec_msns \
	-a 0002:02:00.0,custom_inb_sa=1 \
	-a 0002:1d:00.0,custom_inb_sa=1 \
	-a 0002:20:00.1 -a 0002:1e:00.0 -- --testmode 6 > $LOG &

echo "================================"
while [[ ! -f $LOG ]]; do
	echo "Waiting for log"
	sleep 1
	continue
done
echo "================================"
sleep 1
cat $LOG
$VFIO_DEVBIND -u $IF0
TEST0=$(grep "Test IPSEC_RTE_PMD_CNXK_API_TEST" $LOG | awk '{print $3}')
if [[ $TEST0 != "PASS" ]]; then
	echo "Test IPSEC_RTE_PMD_CNXK_API_TEST FAILED"
	exit 1
fi
echo "IPSEC_RTE_PMD_CNXK_API_TEST SUCCESSFUL"
