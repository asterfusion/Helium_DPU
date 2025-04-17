#!/bin/bash

# check base docker image
docker image inspect fusionnos_base:v1 > /dev/null 2>&1

if [ $? == 1 ];then
    echo "Error: fusionnos base image not exist!"
    echo "Please fetch it from asterfusion share or colleague!"
    exit 1
fi

set -e

commit_id=`git log --pretty=format:"%H" | head -1 | cut -c 1-11`

# clean and copy debs to dir
cd `dirname $0`
rm -rf ./debs
mkdir -p ./debs
cp ../build-root/*.deb ./debs
cp ../build/external/*.deb ./debs

TmpStr=`date +%s%N  | cut -c 5-14`
TmpDockerName="FusionNOS"_"$TmpStr"

echo "Temp docker name : ""$TmpDockerName"

docker run -d \
    --privileged \
    --name $TmpDockerName \
    -v /sys/bus/pci/drivers:/sys/bus/pci/drivers \
    -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
    -v /sys/devices/system/node:/sys/devices/system/node \
    -v /dev:/dev \
    --ulimit core=0:0 \
    fusionnos_base:v1 \
    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf -n

docker cp debs $TmpDockerName:/tmp/
docker cp install.sh $TmpDockerName:/tmp/debs/
docker cp dpdk-devbind.py $TmpDockerName:/usr/local/bin/
docker cp vpp.conf $TmpDockerName:/etc/supervisor/conf.d/

# install
docker exec -i $TmpDockerName /tmp/debs/install.sh

# update supervisorctl
docker exec -i $TmpDockerName supervisorctl update

# export
docker stop $TmpDockerName
docker export $TmpDockerName > fusionnos_docker.tar
docker rm $TmpDockerName

build_exe(){
    time=`date +"%Y%m%d"`
    md5_source=$(md5sum fusionnos_docker.tar | awk '{print $1}')
    file_name=FusionNOS_${time}_Git${commit_id}_docker.bin
    sed -e "s/%%source_md5%%/$md5_source/" ./install_docker.sh > $file_name
    cat fusionnos_docker.tar >> ${file_name}
    chmod +x ${file_name}
    rm fusionnos_docker.tar
    echo 'Source md5 : ' $md5_source
    echo 'New install bin file generated:' ${file_name}
}

build_exe
