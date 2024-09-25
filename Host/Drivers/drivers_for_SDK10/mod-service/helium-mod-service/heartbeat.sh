#/bash/bin
num=`lspci | grep b200 |wc -l`
ping_manage(){
    ping_count=5
    #main-------------------
    
    while true
    do
        j=0
        while [[ $j < $num ]]
        do
            ip=$((j+11))
            host=12.12.12.$ip
            echo "-------->开始检测$host服务器通迅是否正常"
            ping_result=`ping $host -w 2 -c $ping_count |tail -2 |head -1`
            
        
            #取成功条数
            succ_ping=`echo $ping_result | gawk '{print $4}'`
            #echo $succ_ping

            #取失败百分比
            loss_ping=`echo $ping_result | gawk '{print $6}'`
            #echo $loss_ping
                if [ $loss_ping == "100%" ];then
                    echo "网卡侧连接失败，即将重启"
                    
                    /usr/bin/helium_rmmod.sh
                    systemctl restart helium-mod
                else
                    echo "连接正常"
                fi
            let j++
        done
        sleep 60
    done

}

ping_manage