
#!/bin/bash






export MRVL_REMOTE_DEBUG=1

##get env from uboot
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



k=0
LIST_DEV_ID=("b200" "b204" "3380" "a300")
find_host_sid()
{
    
    local __device_id
    local __pci_slot
    local i=0

    export CAVM_PCI_DEVICE=$num
    while read x; do
        __pci_slot=`echo $x|cut -d ' ' -f 3`
     
        # echo $__pci_slot
        __device_id=`setpci -s $__pci_slot DEVICE_ID`
        for index in "${LIST_DEV_ID[@]}"; do
            if [ $index == $__device_id ]; then
                __found=$((__found+1))
                
                PCI_DEVICE_SLOT=$__pci_slot
                host_str1[$i]=${PCI_DEVICE_SLOT:5:2}
                echo ${host_str1[$i]}
               
                host_bus=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$PCI_DEVICE_SLOT")))

                host_pid_o=${host_bus#*:}
                host_pid=${host_pid_o:0:2}
                # echo $host_pid
                host_sid[$i]=$host_pid
                #echo ${host_sid[$i]}
                let i+=1
            fi
        done
    done <<-EOF
        $(/usr/bin/mrvl-remote-reset | grep 0000:)
EOF
}
find_ko_sid(){



    while read line
    do 
        
        
        lines[k]=${line#*=}
        #echo ${lines[k]}
    
        
        let k+=1
    done </etc/helium_mod.conf

    
    path_octeon_drv_pre=${lines[3]}
    echo $path_octeon_drv_pre
    
    dmesg -c
    insmod $path_octeon_drv_pre 
    if [[ $? -eq 0 ]]
    then 
        echo "insmod octeon_drv_pre.kosuccessfully"
    fi
    rmmod octeon_drv_pre.ko
    local __device_id
    local __pci_slot
    local i=0
    echo 'find_ko_sid'
    
    LIST_DEV_ID=("b200" "b204" "3380" "a300")
    while read x; do
        echo $x
        str1=${x#*bus=}
        
        echo $str1
        #str2=${str1:0:2}
        str3=${str1%%:*}
        echo $str3
        num_str=`expr length $str3`
        if [ $num_str == 1 ]
        then 
           str2="0$str3"
        else
            str2=$str3
        fi
        __pci_slot="$str2:00.0"
        #echo $__pci_slot
        __device_id=`setpci -s $__pci_slot DEVICE_ID`
        for index in "${LIST_DEV_ID[@]}"; do
            if [ $index == $__device_id ]; then
                __found=$((__found+1))
                
                host_str2[$i]=$str2
                
             
               
                echo ${host_str2[$i]}
                let i+=1
            fi
        done
    done <<-EOF
        $(dmesg |grep ordering_octeon)
EOF

}

make_rank(){
    local i=0
    local j=0
    
    echo $j
    echo ' go' 
  
    echo ' '
    while (( i < num ))
    do
        echo ${host_str1[$i]}
        while (( j < num ))
        
        do
            echo ${host_str2[$j]}
            if [ ${host_str1[$i]} == ${host_str2[$j]} ]
            then
                rank[$j]=$i
                echo $j
                echo ${rank[$j]}
                
            fi
            let j++
        done
        let i++
        j=0
        echo ' '
    done
}



multi_device_ins(){

    j=0
    
    echo "0" >/tmp/ins.conf
    while [[ $j < $num ]]
    do
        rank=${rank[$j]}
        echo "wait for resetting device_$j"
        /usr/bin/helium_reset.sh $rank $j ${host_sid[rank]} &
        # export CAVM_PCI_DEVICE=$rank
        
        # /usr/bin/mrvl-remote-reset
        # /usr/bin/mrvl-remote-bootcmd 'st'
        # /usr/bin/mrvl-remote-bootcmd "setenv host_pid ${host_sid[rank]}"
        # /usr/bin/mrvl-remote-bootcmd "setenv device_num $j"
        # uboot_get_env mac_eth0 128 __ethaddr
        # uboot_get_env use_env_addr 128  __use_env_addr
        # if [[ "$__use_env_addr" = "1" ]]
        # then
        #     /usr/bin/mrvl-remote-bootcmd "setenv ethaddr $__ethaddr"
     
           
        # fi



        # /usr/bin/mrvl-remote-bootcmd 'saveenv'
        # sleep 5
        # /usr/bin/mrvl-remote-reset
        let j++
    done

    n=0
    while [ $n -ne $num ]
    do
        n=`awk '{print $1}' /tmp/ins.conf`
        echo $n
        sleep 1
    done
 
   
    k=0     
    while read line
    do 
    
    
    lines[k]=${line#*=}
    #echo ${lines[k]}

    
    let k+=1
    done </etc/helium_mod.conf

    path_mgmt_net=${lines[0]}
    echo $path_mgmt_net
    path_octeon_drv=${lines[1]}
    echo $path_octeon_drv

    vf_num=${lines[2]}

    octnic=${lines[4]}
    echo $octnic

    insmod $path_octeon_drv num_vfs=$vf_num
    if [[ $? -eq 0 ]]
    then 
    echo "insmod octeon_drv.ko,vfs_num="$vf_num" successfully"
    fi


    
    insmod $path_mgmt_net
    if [[ $? -eq 0 ]]
    then 
    echo "insmod mgmt_net.ko successfully"
    fi

    
    j=0
    echo "create network bridge"
    brctl addbr octbr


    ifconfig octbr 12.12.12.1
    ifconfig octbr up

    if [ $num -eq 1 ];then
       
        if [[ $__ethaddr != '' ]]
        then
            insmod $octnic
            if [[ $? -eq 0 ]]
            then
            echo "insmod octnic successfully"
            sleep 5
            
            echo "ifconfig oct0 hw ether $__ethaddr"
            ifconfig oct0 hw ether $__ethaddr
            ifconfig oct0 up
            netplan apply
            ifconfig octbr 12.12.12.1
            fi
        fi
    fi
    

}


num=`lspci | grep b200 |wc -l`
if [ $num != 0 ]
then
find_host_sid
find_ko_sid
make_rank

fi
    
multi_device_ins
    
/usr/bin/mvmrest.sh>/dev/null 2>&1 &

