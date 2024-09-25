#!/bin/bash

rank=$1
j=$2
host_pid=$3


export CAVM_PCI_DEVICE=$rank

uboot_get_env()
{
	local __ubootvar=$1
	local __ubootvarlen=$2
    #len=   len('var=var')
	local __retval=$3
	local __pcimemstr

	if [ $# -lt 3 ]; then
		echo "Invalid parameter."
		__exit 1
	fi

	# export the specified environment variable to memory
	/usr/bin/mrvl-remote-bootcmd "env export -b 0x20000000 ${__ubootvar}" &> /dev/null

	# read env var setting from memory and convert to ASCII
	__pcimemstr=`/usr/bin/mrvl-remote-memory -w 1 -c ${__ubootvarlen} 0x20000000 2> /dev/null | grep -vi "PCIE port"`
	__pcimemstr=`echo "${__pcimemstr}" | sed "s/\(.*\) : \(.*\)/\2/g" | xxd -p -r`
	__pcimemstr=`echo "${__pcimemstr}" | cut -d= -f 2-`

	# return the value to caller
	eval $__retval="'${__pcimemstr}'"
}

/usr/bin/mrvl-remote-reset
n=`awk '{print $1}' /tmp/ins.conf`
n=$((n+1))
echo $n > /tmp/ins.conf

/usr/bin/mrvl-remote-bootcmd 'st'
/usr/bin/mrvl-remote-bootcmd "setenv host_pid $host_pid"
/usr/bin/mrvl-remote-bootcmd "setenv device_num $j"
uboot_get_env mac_eth0 128 __ethaddr
uboot_get_env use_env_addr 128  __use_env_addr
if [[ "$__use_env_addr" = "1" ]]
then
    /usr/bin/mrvl-remote-bootcmd "setenv ethaddr $__ethaddr"


fi


export CAVM_PCI_DEVICE=$rank
/usr/bin/mrvl-remote-bootcmd 'saveenv'
sleep 5
export CAVM_PCI_DEVICE=$rank
/usr/bin/mrvl-remote-reset