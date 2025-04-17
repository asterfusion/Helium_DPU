#!/bin/sh -e
#cpu upgrade
workingdir=`dirname $0`
ARCHIVE=`awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0`
tail -n +$ARCHIVE $0 > $workingdir/fusionnos_docker.tar
source_md5=%%source_md5%%
echo 'Source md5 : ' $source_md5
md5_source=`md5sum $workingdir/fusionnos_docker.tar | awk '{ print $1 }'`
if [ $md5_source != $source_md5 ];then
   echo
   echo ">>>ERROR: Unable to verify source archive checksum"
   echo ">>>Expected: $md5_source"
   echo ">>>Found   : $source_md5"
   exit 1
else
    echo "Md5 verify pass!"
fi

# remove old if exist
set +e
docker container inspect FusionNOS > /dev/null 2>&1
if [ $? == 0 ];then
    echo "old container exist!removing..."
    docker stop FusionNOS
    docker rm FusionNOS
    echo "old container removed."
fi
docker image inspect fusionnos > /dev/null 2>&1
if [ $? == 0 ];then
    echo "old image exist!removing..."
    docker rmi fusionnos
    echo "old image removed."
fi
set -e

# do we need to save files? No for now.

# install new
docker import $workingdir/fusionnos_docker.tar fusionnos

echo 'install docker instance'
docker run \
        -d \
        --privileged \
        -v /sys/bus/pci/drivers:/sys/bus/pci/drivers \
        -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
        -v /sys/devices/system/node:/sys/devices/system/node \
        -v /dev:/dev \
        --name FusionNOS \
        --ulimit core=0:0 \
        --restart always \
        fusionnos /usr/bin/supervisord -c /etc/supervisor/supervisord.conf -n

# install vppctl cmd at host server
echo '#!/bin/bash' > /usr/local/bin/vppctl
echo 'docker exec -it FusionNOS vppctl $@' > /usr/local/bin/vppctl
chmod +x /usr/local/bin/vppctl

echo 'Clear install source file'
rm -rf $workingdir/fusionnos_docker.tar

echo 'Install complete!'
exit 0

__ARCHIVE_BELOW__
