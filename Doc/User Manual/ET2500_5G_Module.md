## 1 Check that the driver is loaded correctly

- cd /sys/bus/usb/drivers
check *option、qmi_wwan_q、cdc_mbim* exist

The RM520N should support both `qmi_wwan_q` and `cdc_mbim` driver modes. Currently, `qmi_wwan_q` is being used.

- check driver insmod

```bash
lsmod | grep qmi_wwan_q 
```

- if driver not exists，get lastest kernel source code from github

https://github.com/asterfusion/DPU_linux_kernel.git

## 2 Check Hardware

- The SIM card is properly inserted
- The antenna is connected

## 3 Compile busybox

- download url ：[https://busybox.net](https://busybox.net/)
- config

```bash
sed -i 's/CONFIG_SHA1_HWACCEL=y/# CONFIG_SHA1_HWACCEL is not set/' .config
make oldconfig
//make sure CONFIG_UDHCPC is on
```

- compile

```bash
sudo apt install libncurses-dev
make
make install
```

- copy default file to default path

```bash
sudo cp example/udhcp/simple.script /usr/share/udhcpc/default.script
// Copy this file to the current system directory. If udhcpc does not exist, create it manually.

```

## 3 Compile Quectel_QConnectManager

```
	git clone https://github.com/asterfusion/Helium_DPU.git
	cd Helium_DPU/ET2500/Quectel_QConnectManager
	make

```

## 4 **Dial-up Internet access**

```
	cd Quectel_QConnectManager_Linux_V1.6.8
	sudo ./quectel-CM -s cment &

```

### Dial-up connection established log

```
	02-04_10:07:36:544] QConnectManager_Linux_V1.6.8
	[02-04_10:07:36:544] Find /sys/bus/usb/devices/4-1.2 idVendor=0x2c7c idProduct=0x801, bus=0x004, dev=0x003
	[02-04_10:07:36:544] Auto find qmichannel = /dev/cdc-wdm0
	[02-04_10:07:36:544] Auto find usbnet_adapter = wwx023bd8b8f158
	[02-04_10:07:36:544] netcard driver = qmi_wwan_q, driver version = V1.2.9
	[02-04_10:07:36:544] qmap_mode = 1, qmap_version = 9, qmap_size = 31744, muxid = 0x81, qmap_netcard = wwan0_1
	[02-04_10:07:36:544] Modem works in QMI mode
	[02-04_10:07:36:580] /proc/4745/fd/7 -> /dev/cdc-wdm0
	[02-04_10:07:36:580] /proc/4745/exe -> /home/admin/Quectel_QConnectManager_Linux_V1.6.8/quectel-CM
	[02-04_10:07:36:582] requestDeactivateDefaultPDP WdsConnectionIPv4Handle
	admin@sonic:~/Quectel_QConnectManager_Linux_V1.6.8$ [02-04_10:07:36:991] ip link set dev wwx023bd8b8f158 down
	[02-04_10:07:36:999] ip addr flush dev wwan0_1
	[02-04_10:07:37:005] ip link set dev wwan0_1 down
	[02-04_10:07:37:183] QmiWwanThread exit
	[02-04_10:07:37:189] qmi_main exit
	[02-04_10:07:38:582] cdc_wdm_fd = 7
	[02-04_10:07:38:654] Get clientWDS = 15
	[02-04_10:07:38:687] Get clientDMS = 1
	[02-04_10:07:38:719] Get clientNAS = 3
	[02-04_10:07:38:751] Get clientUIM = 2
	[02-04_10:07:38:783] Get clientWDA = 1
	[02-04_10:07:38:814] requestBaseBandVersion RM520NCNAAR05A02M4G
	[02-04_10:07:38:846] qmap_settings.rx_urb_size = 31744
	[02-04_10:07:38:846] qmap_settings.ul_data_aggregation_max_datagrams  = 11
	[02-04_10:07:38:846] qmap_settings.ul_data_aggregation_max_size       = 8192
	[02-04_10:07:38:846] qmap_settings.dl_minimum_padding                 = 0
	[02-04_10:07:38:974] requestGetSIMStatus SIMStatus: SIM_READY  //如果未ready，检查sim卡状态
	[02-04_10:07:39:039] requestGetProfile[pdp:1 index:1] cment///0/IPV4
	[02-04_10:07:39:039] requestSetProfile[pdp:1 index:1] cment///0/IPV4
	[02-04_10:07:39:039] no need to set skip the rest
	[02-04_10:07:39:071] requestRegistrationState2 MCC: 460, MNC: 0, PS: Attached, DataCap: 5G_SA //如果未attached，检查天线和信号
	[02-04_10:07:39:103] requestQueryDataCall IPv4ConnectionStatus: DISCONNECTED
	[02-04_10:07:39:103] ip link set dev wwx023bd8b8f158 down
	[02-04_10:07:39:104] ip addr flush dev wwan0_1
	[02-04_10:07:39:107] ip link set dev wwan0_1 down
	[02-04_10:07:39:615] requestSetupDataCall WdsConnectionIPv4Handle: 0xe2bfdb40
	[02-04_10:07:39:743] ip link set dev wwx023bd8b8f158 up
	[02-04_10:07:39:748] ip link set dev wwan0_1 up
	[02-04_10:07:39:751] busybox udhcpc -f -n -q -t 5 -i wwan0_1
	udhcpc: started, v1.35.0
	udhcpc: broadcasting discover
	udhcpc: broadcasting select for 10.139.61.221, server 10.139.61.222
	udhcpc: lease of 10.139.61.221 obtained from 10.139.61.222, lease time 7200
	[02-04_10:07:39:867] ip -4 address flush dev wwan0_1
	[02-04_10:07:39:869] ip -4 address add 10.139.61.221/30 dev wwan0_1
	[02-04_10:07:39:870] ip -4 route add default via 10.139.61.222 dev wwan0_1
	[1]-  Done                    sudo ./quectel-CM -s cment

```

## 5 AT command

USB2 is an AT serial port device. Use a serial terminal tool to connect to the serial port.
minicom /dev/tty/USB2

### Check Signal Status

**Command:**

```
AT+QENG="SERVINGCELL"
```

**Response:**

```
+QENG:"servingcell","NOCONN","NR5G-SA","TDD",460,00,A0117F003,287,1000D7,504990,41,12,-99,-13,0,1,20
```

```cpp
// Focus mainly on the network type:// NR5G-SA  : 5G Standalone
// NR5G-NSA : 5G Non-Standalone
// LTE      : 4G
// -99 indicates the signal received power; values <= -110 indicate very poor signal
// -13 indicates the reference signal received quality; values < -15 indicate very poor quality
```