#!/bin/bash

# one_device_rm(){

#     ifconfig mvmgmt0 down
#     if [[ $? -eq 0 ]];
#     then
#         echo "down mvmgmt successfully"
#     fi   
#     sleep 2
#     rmmod mgmt_net 
#     if [ $? -eq 0 ];
#     then
#         echo "rmmod mgmt_net successfully"
#     fi   
#     sleep 2
#     rmmod octeon_drv
#     if [ $? -eq 0 ];
#     then
#         echo "rmmod octeon_drv successfully"
#     fi   
#     sleep 2

# }

multi_device_rm(){

    pid_mvmreset=`ps -ef | grep /usr/bin/mvmrest.sh |sed -n 1p|awk '{print $2}'`
    kill -9 $pid_mvmreset





    if [ $num -eq 1 ];then
        if_exsit=`ifconfig -a| grep oct0`
        if [[ $if_exsit != '' ]]
        then
            ifconfig oct0 down
            rmmod octnic
            if [ $? -eq 0 ];
            then
                echo "rmmod octnic  successfully"
            fi 
        fi
    fi
    sleep 5
    ifconfig octbr down
    brctl delbr octbr
    if [ $? -eq 0 ];
    then
        echo "del network bridge successfully"
    fi 
    j=0
	
	while [[ $j < $num ]]
	do
		mvmgmt="mvmgmt$j"
		ifconfig $mvmgmt down
        if [[ $? -eq 0 ]];
        then
            echo "down $mvmgmt successfully"
        fi  

		let j++
	done
   
    rmmod mgmt_net 
    if [ $? -eq 0 ];
    then
        echo "rmmod mgmt_net successfully"
    fi   
    sleep 2


    rmmod octeon_drv
    if [ $? -eq 0 ];
    then
        echo "rmmod octeon_drv successfully"
    fi   
    

    



}

num=`lspci | grep b200 |wc -l`

    
multi_device_rm
    

