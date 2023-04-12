# How to test octeontx2 zip
```
modprobe octeontx_zip
dpdk-devbind.py -b vfio-pci 0001:04:00.1 0001:04:00.2 0001:04:00.3 0001:04:00.4 0001:04:00.5 0001:04:00.6 0001:04:00.7 0001:04:01.0

#the core num should equal to the zip device num, core 1 is for control-plane, 2,3 is for data-plane
./build/app/dpdk-test-compress-perf -l 1-3 -w 0001:04:00.1 -w 0001:04:00.2 -- --driver-name compress_octeontx --input-file doc/build-sdk-quick.txt --seg-sz 59460 --num-iter 1000 --huffman-enc fixed
```
