# Test examples
## config event device
```
echo "177d a0f9" > /sys/bus/pci/drivers/vfio-pci/new_id
dpdk-devbind.py -b vfio-pci 0002:0e:00.0
dpdk-devbind.py -b vfio-pci 0002:02:00.0
dpdk-devbind.py -b vfio-pci 0002:03:00.0

echo 0 > /sys/bus/pci/devices/0002:06:00.0/limits/sso
echo 0 > /sys/bus/pci/devices/0002:07:00.0/limits/sso
echo 0 > /sys/bus/pci/devices/0002:08:00.0/limits/sso
echo 0 > /sys/bus/pci/devices/0002:09:00.0/limits/sso
echo 0 > /sys/bus/pci/devices/0002:0a:00.0/limits/sso
echo 0 > /sys/bus/pci/devices/0002:0b:00.0/limits/sso
echo 0 > /sys/bus/pci/devices/0002:0e:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:06:00.0/limits/ssow
echo 0 > /sys/bus/pci/devices/0002:07:00.0/limits/ssow
echo 0 > /sys/bus/pci/devices/0002:08:00.0/limits/ssow
echo 0 > /sys/bus/pci/devices/0002:09:00.0/limits/ssow
echo 0 > /sys/bus/pci/devices/0002:0a:00.0/limits/ssow
echo 0 > /sys/bus/pci/devices/0002:0b:00.0/limits/ssow
echo 0 > /sys/bus/pci/devices/0002:0e:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:0e:00.0/limits/tim
echo 1 > /sys/bus/pci/devices/0002:0e:00.0/limits/npa
echo 16 > /sys/bus/pci/devices/0002:0e:00.0/limits/sso
echo 40 > /sys/bus/pci/devices/0002:0e:00.0/limits/ssow
```

## start mp_server and client
```
cd examples/multi_process/client_server_mp/mp_server
./build/app/mp_server -l 1-4 -w 0002:02:00.0 -w 0002:03:00.0 -w 0002:0e:00.0 -- -p 0x3 -n 2
```

```
cd examples/multi_process
./client_server_mp/mp_client/build/app/mp_client -l 15 --proc-type=auto -- -n 0
```

```
cd examples/multi_process
./client_server_mp/mp_client/build/app/mp_client -l 14 --proc-type=auto -- -n 1
```
