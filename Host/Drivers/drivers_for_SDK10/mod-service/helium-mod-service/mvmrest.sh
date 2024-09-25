#/bash/bin

while true
do
    j=0
    # num_octbr=`brctl show octbr | wc -l`
    num_octbr=`brctl show octbr |sed -n '2,$p'|awk '{if(length !=0) print $4}'|wc -l`
    octbr_one=`brctl show octbr |sed -n '2,$p'|awk '{if(length !=0) print $4}'`
  
    num_device=`lspci | grep b200 |wc -l`
    num_device_all=$num_device
   
     if [[ $num_device_all -eq 1 ]];then
           
            if [[ $octbr_one == "mvmgmt0" ]];then
                echo $octbr_one >/dev/null
            else
             echo "mvmgmt had reset"
                 brctl addif octbr mvmgmt0
            fi
    fi




    if [[ $num_octbr != $num_device_all ]];then
       
        echo "mvmgmt had reset"
          while [[ $j < $num_device ]]
             do
                mvmgmt="mvmgmt$j"
                 brctl addif octbr $mvmgmt
                ifconfig $mvmgmt up
                let j++
            done
       
    fi
    sleep 5
done

