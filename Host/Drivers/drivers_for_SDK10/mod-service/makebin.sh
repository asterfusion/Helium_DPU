#!/bin/bash
set -o errexit
#安装路径
dir_tmp=/usr/bin/
type=`uname -m`

echo -e "\t ready to install helium-mod..."

sed -n -e '1,/^exit 0$/!p' $0 > /tmp/helium-mod-service.tar.gz 2>/dev/null

cd /tmp
#将分离出的脚本解压缩到/tmp文件夹下
echo -e "mgmt_net_path=/usr/bin/mgmt_net.ko\nocteon_drv_path=/usr/bin/octeon_drv.ko\nvf_num=4\nocteon_dev_pre=/usr/bin/octeon_drv_pre.ko\noctnic_path=">/etc/helium_mod.conf

tar xzf helium-mod-service.tar.gz -C /tmp
chmod +x /tmp/helium-mod-service/*.sh
cp /tmp/helium-mod-service/*.sh $dir_tmp

if [[ -f /tmp/helium-mod-service/*.ko ]]
then
 cp /tmp/helium-mod-service/*.ko $dir_tmp
fi
cp /tmp/helium-mod-service/*.service /usr/lib/systemd/system/

if [ "$type" = "x86_64" ]
then
cp /tmp/helium-mod-service/mrvl_x86/mrvl* /$dir_tmp
else
cp /tmp/helium-mod-service/mrvl_arm/mrvl* /$dir_tmp
fi
#解压完成后删除压缩包
rm -rf helium-mod-service.tar.gz
rm -rf /tmp/helium-mod-service

systemctl daemon-reload
systemctl enable helium-mod.service
echo -e "\t install successfully"
exit 0
