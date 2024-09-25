
#!/bin/bash

arg_get=$1
arg=$((arg_get-1))
#echo "$arg"
num=`lspci | grep b200 |wc -l`
if [[ $arg =~ ^[1-9][0-9]*|0$ ]]; then
    if [[ $arg -ge $num ]];then
        echo "error num , max num of divice is $num"
        exit
    fi

else
    echo "please enter 1~$num"
    exit
fi

export MRVL_REMOTE_DEBUG=1
k=0
LIST_DEV_ID=("b200" "b204" "3380" "a300")
find_host_sid()
{
    
    local __device_id
    local __pci_slot
    i=0
    
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
                
               # echo ${host_str1[$i]}
              # echo "$PCI_DEVICE_SLOT"
              
       
                host_bus=$(basename $(dirname $(readlink "/sys/bus/pci/devices/$PCI_DEVICE_SLOT")))

                host_pid_o=${host_bus#*:}
                host_pid=${host_pid_o:0:2}
           
                host_sid[$i]=$host_pid
               
                let i+=1
            fi
        done
    done <<-EOF
        $(/usr/bin/mrvl-remote-reset | grep 0000:)
EOF
}

find_ko_sid(){

    local __device_id
    local __pci_slot
    local i=0
  
    
    LIST_DEV_ID=("b200" "b204" "3380" "a300")
    while read x; do
  
        str1=${x#*bus=}
      
        str3=${str1%%:*}
        
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
                
             
               
                #echo ${host_str2[$i]}
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
    
    
    while (( i < num ))
    do
      
        while (( j < num ))
        
        do
            #echo ${host_str2[$j]}
            if [ ${host_str1[$i]} == ${host_str2[$j]} ]
            then
                rank[$j]=$i
              
                
            fi
            let j++
        done
        let i++
        j=0
      
    done
}



find_host_sid
find_ko_sid
make_rank
rank=${rank[$arg]}
export CAVM_PCI_DEVICE=$rank

/usr/bin/mrvl-remote-reset

# j=0
# while(($j<$i))
# do
#         if [ "${host_str1[$j]}" == "$arg_str" ];then
#                     export CAVM_PCI_DEVICE=$j
#                     echo "CAVM_PCI_DEVICE=$j"
#                 fi
#                  let "j++"
#              done
