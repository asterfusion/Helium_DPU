#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
source $CNXKTESTPATH/../common/testpmd/common.env
source $CNXKTESTPATH/../common/remote/command.env
LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-"/tmp/dpdk/deps/lib"}
REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
TPMD_PROMPT="^testpmd> $"
TPMD_PFIX="endpoint"
EP_BOARD=${EP_BOARD:?}
EP_HOST_IF=${EP_HOST_IF:-$(lspci -d :ba03 | head -1 | awk '{ print $1 }')}
EP_BOARD_IF=${EP_BOARD_IF:-0002:20:00.2}

# Start testpmd in EP board
bin=$(find_bin $EP_BOARD dpdk-testpmd $REMOTE_DIR)
bin_args="-l 1-3 -a $EP_BOARD_IF -- -i --port-topology=loop"
board_in_file=$(run_bin --remote $EP_BOARD --bin mktemp)
board_out_file=$(run_bin --remote $EP_BOARD --bin mktemp)
(run_bin --remote $EP_BOARD --bin "sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH stdbuf -o0 $bin" \
	--bin_args "$bin_args" --in_file $board_in_file --out_file $board_out_file --bg_ena) &

wait_for_prompt $EP_BOARD $board_out_file "$TPMD_PROMPT"
write_file $EP_BOARD $board_in_file "start"

# Start testpmd in EP host
testpmd_launch $TPMD_PFIX "-l 0-3 -a $EP_HOST_IF --vdev eth_pcap0,rx_pcap=in.pcap,tx_pcap=out.pcap" \
	"--port-topology=paired --no-flush-rx"
testpmd_cmd $TPMD_PFIX "start"

# Wait for packets
timeout 60 bash -c "
	while [ ! -s out.pcap ]; do
		continue
	done
"

set +e
# Compare pcap files
diff <(tcpdump -r in.pcap -Xvt) <(tcpdump -r out.pcap -Xvt)
match=$?
set -e

if [ $match -eq 1 ]; then
	echo "Transmitted and received packets checksum do not match."
	testpmd_log $TPMD_PFIX
	write_file $EP_BOARD $board_in_file "show port stats all"
	read_file $EP_BOARD $board_out_file
else
	echo "Transmitted and received packets checksum match."
fi

# Cleanup
testpmd_quit $TPMD_PFIX
testpmd_cleanup $TPMD_PFIX
write_file $EP_BOARD $board_in_file "quit"
run_bin --remote $EP_BOARD --bin rm --bin_args "$board_in_file $board_out_file"

exit $match
