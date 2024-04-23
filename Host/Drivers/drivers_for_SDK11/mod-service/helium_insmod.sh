#!/bin/bash
 k=0     
    while read line
    do 
    
    
    lines[k]=${line#*=}
    #echo ${lines[k]}

    
    let k+=1
    done </etc/helium_mod.conf

    octeon_ep=${lines[0]}
    echo $octeon_ep
    octeon_ep_vf=${lines[1]}
    echo $octeon_ep_vf
	vf_num=${lines[2]}
	echo $vf_num

insmod $octeon_ep
if [[ $? -eq 0 ]]
    then 
    echo "insmod octeon_ep.ko successfully"
    else
	echo "insmod octeon_ep.ko failed"
	exit 0
fi

i=0
num=0
mapfile -t device_ids < <(lspci | grep Cavium | awk '{print $1}')
while [ $i = 0 ]
do
	if [ $i = 1 ];then

		break
	else
		echo "wait for octeon_ep"
		sleep 5
		num=$num+1

		
	fi
	if [ $num = 20 ];then 
		echo "time out ,failed"
		exit 0
	fi


	for device_id in "${device_ids[@]}"; do
		echo "echo $vf_num > /sys/bus/pci/devices/0000:$device_id/sriov_numvfs"
		sudo echo $vf_num > /sys/bus/pci/devices/0000:$device_id/sriov_numvfs
		status=$?
		if [ $status -eq 0 ]; then
		echo "echo $vf_num > /sys/bus/pci/devices/0000:$device_id/sriov_numvfs successfully"
		i=1
		else
	
		i=0
		fi
	done
	
done
sleep 5 
insmod $octeon_ep_vf
if [[ $? -eq 0 ]]
    then 
    echo "insmod octeon_ep_vf.ko successfully"
    else
	echo "insmod octeon_ep_vf.ko failed"
	exit 0
fi

