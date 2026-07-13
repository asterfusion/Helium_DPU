#5G Module Linux User Manual

This document guides customers through driver verification, dial-up tool compilation, dial-up networking, AT command checks, and common troubleshooting for the RM520N series 5G module on Linux.

This document assumes that the customer environment already uses a valid USB network interface mode. Customers do not need to modify the module network interface mode. The main control node used in this guide is `/dev/cdc-wdm0`, and the dial-up tool is `quectel-CM`.

## 1. Pre-Use Checklist

Confirm the following hardware conditions before use:

- The SIM card is correctly inserted, and the data service plan is active.
- The antenna is connected, and 4G/5G network coverage is available at the current location.
- The Linux system can detect the related USB device nodes of the module.

## 2. Common Module Device Nodes

Common interfaces are shown below:

| Device Node | Purpose |
| --- | --- |
| `/dev/ttyUSB0` | DIAG |
| `/dev/ttyUSB1` | GNSS |
| `/dev/ttyUSB2` | AT commands |
| `/dev/ttyUSB3` | Modem |
| `/dev/cdc-wdm0` | QMI/MBIM control node |
| `wwan0` or `wwan0_1` | Data network interface |

Note: `/dev/cdc-wdm0` is the control node. After dial-up, actual data transmission is performed through a network interface such as `wwan0`. The actual interface name depends on the system detection result and the `quectel-CM` log.

## 3. Check Driver and Device Status

Check whether related drivers exist:

```bash
ls /sys/bus/usb/drivers | grep -E 'option|cdc_wdm|qmi_wwan|qmi_wwan_q|cdc_mbim'
```

Check kernel modules:

```bash
lsmod | grep -E 'option|cdc_wdm|qmi_wwan|qmi_wwan_q|cdc_mbim'
```

Check device nodes:

```bash
ls -l /dev/ttyUSB* /dev/cdc-wdm* 2>/dev/null
```

Check network interfaces:

```bash
ip link
```

Check kernel logs:

```bash
dmesg | grep -iE '2c7c|ttyUSB|cdc-wdm|qmi|mbim|wwan'
```

Check the driver bound to the actual network interface:

```bash
ethtool -i wwan0
```

## 4. Confirm and Switch to the cdc_mbim Driver

At the customer site, first confirm the driver currently bound to `wwan0`:

```bash
ethtool -i wwan0
```

If the `driver` field is `cdc_mbim`, the current driver is correct and you can continue with the dial-up steps.

Example:

```text
driver: cdc_mbim
version: ...
firmware-version: ...
bus-info: ...
```

If the `driver` field is not `cdc_mbim`, use AT commands to switch the module USB network interface mode to MBIM, and then restart the module to make the configuration take effect.

Open the AT command port:

```bash
sudo minicom -D /dev/ttyUSB2
```

Or:

```bash
microcom /dev/ttyUSB2
```

Run the following AT commands:

```text
AT+QCFG="usbnet",2
AT+CFUN=1,1
```

Notes:

- `AT+QCFG="usbnet",2` sets the USB network interface mode to MBIM.
- `AT+CFUN=1,1` restarts the module so the configuration can take effect.
- After the module restarts, wait for the USB device to enumerate again, and then check the `wwan0` driver again.

After the restart, confirm again:

```bash
ethtool -i wwan0
```

After confirming that the `driver` field is `cdc_mbim`, continue with dial-up.

## 5. Compile the Dial-Up Tool

Dial-up uses `quectel-CM` from the `QConnectManager` tool package.

`QConnectManager` usually generates the following programs:

| Program | Purpose |
| --- | --- |
| `quectel-CM` | Main dial-up program |
| `quectel-qmi-proxy` | QMI multi-PDN dial-up proxy |
| `quectel-mbim-proxy` | MBIM multi-PDN dial-up proxy |

Obtain the source code:

```bash
git clone https://github.com/asterfusion/Helium_DPU.git
cd ET2500/Quectel_QConnectManager
```

Enter the source directory and run:

```bash
make
```

For cross-compilation, use:

```bash
make CROSS_COMPILE=<cross-compiler-prefix>
```

Example:

```bash
make CROSS_COMPILE=aarch64-linux-gnu-
```

After compilation, confirm that the executable files exist:

```bash
ls -l quectel-CM quectel-qmi-proxy quectel-mbim-proxy
```

## 6. Dial-Up Networking

Confirm the APN before dialing. The example APN in this document is `cment`. Replace it according to the requirements of the actual SIM card operator.

Single IPv4 dial-up:

```bash
sudo ./quectel-CM -s cment -4 &
```

If `-4` or `-6` is not specified, the tool usually uses IPv4 by default:

```bash
sudo ./quectel-CM -s cment &
```

If the system has multiple modules or multiple mobile network interfaces, specify the interface:

```bash
sudo ./quectel-CM -s cment -4 -i wwan0 &
```

If the actual network interface is `wwan0_1`, use:

```bash
sudo ./quectel-CM -s cment -4 -i wwan0_1 &
```

Disconnect dial-up:

```bash
sudo killall quectel-CM
```

Run with logs for troubleshooting:

```bash
sudo ./quectel-CM -s cment -4 -v -f quectel-cm.log -u usbmon.log &
```

## 7. Confirm Successful Dial-Up

When dial-up succeeds, the `quectel-CM` log usually contains the following key information:

```text
Auto find qmichannel = /dev/cdc-wdm0
Auto find usbnet_adapter = <netdev>
requestGetSIMStatus SIMStatus: SIM_READY
requestRegistrationState2 ... PS: Attached, DataCap: 5G_SA
requestSetupDataCall ...
lease of <ip> obtained from <server>
ip -4 address add <ip>/<prefix> dev <netdev>
ip -4 route add default via <gateway> dev <netdev>
```

Confirm the following key items:

| Log Item | Expected Result |
| --- | --- |
| SIM status | `SIM_READY` |
| Network registration | `PS: Attached` |
| Network capability | `5G_SA`, `5G_NSA`, or LTE |
| Control node | `/dev/cdc-wdm0` |
| Data network interface | `wwan0`, `wwan0_1`, etc. |
| IP address | IPv4/IPv6 address obtained successfully |
| Default route | The default route points to the module network interface |

Successful dial-up logs are provided in `ET2500/Quectel_QConnectManager/log`. Mainly check `cdc_mbim.txt`.

## 8. Check the Network After Dial-Up

Check the network interface address:

```bash
ip addr show wwan0
```

Check routes:

```bash
ip route
```

Confirm the outbound interface used to access the Internet:

```bash
ip route get 8.8.8.8
```

Test IP connectivity:

```bash
ping -c 4 8.8.8.8
```

Test domain name resolution:

```bash
cat /etc/resolv.conf
ping -c 4 www.baidu.com
```

If an IP address can be pinged but a domain name cannot, check the DNS configuration first.

## 9. Use AT Commands

The common AT command port of the 5G module is:

```text
/dev/ttyUSB2
```

Use `minicom`:

```bash
sudo minicom -D /dev/ttyUSB2
```

Or use `microcom`:

```bash
microcom /dev/ttyUSB2
```

Common AT commands are shown below:

```text
ATI
AT+CPIN?
AT+COPS?
AT+CSQ
AT+CEREG?
AT+C5GREG?
AT+QENG="SERVINGCELL"
AT+CGDCONT?
```

Check SIM status:

```text
AT+CPIN?
```

Expected response:

```text
+CPIN: READY
OK
```

Check serving cell and signal:

```text
AT+QENG="SERVINGCELL"
```

Example:

```text
+QENG:"servingcell","NOCONN","NR5G-SA","TDD",460,00,A0117F003,287,1000D7,504990,41,12,-99,-13,0,1,20
```

Focus on the following fields:

| Field | Description |
| --- | --- |
| `NR5G-SA` | 5G standalone mode |
| `NR5G-NSA` | 5G non-standalone mode |
| `LTE` | 4G network |
| RSRP, such as `-99` | Received power. A value closer to -44 is better; lower than -110 is usually poor. |
| RSRQ, such as `-13` | Received quality. Lower than -15 is usually poor. |

For detailed commands, refer to `Helium_DPU/Doc/User Manual/5G Module Series AT Commands Manual.md`.

## 10. Check APN and PDP Configuration

Check the current PDP configuration:

```text
AT+CGDCONT?
```

Example:

```text
+CGDCONT: 1,"IP","cmnet","0.0.0.0",0,0,0,0
+CGDCONT: 2,"IPV4V6","ims","0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",0,0,0,0
+CGDCONT: 3,"IPV4V6","SOS","0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",0,0,0,1
```

To set the APN for normal data service, use:

```text
AT+CGDCONT=1,"IP","cment"
```

Replace the APN according to the operator requirements, for example `cmnet`, `cment`, or a dedicated APN for the customer's SIM card.

Notes:

- PDP contexts such as `ims` and `SOS` are usually used by internal module services. They are not recommended for normal data dial-up.
- If a PDP context without APN configuration is used, configure the APN before dialing.
- `quectel-CM -s <APN>` sets or confirms the dial-up profile during the dial-up process.

## 11. Multi-PDN Dial-Up

Normal customer scenarios usually require only single dial-up.

If multiple PDNs are required, use a proxy program according to the actual driver type and specify the PDN ID with `-n`.

MBIM multi-PDN dial-up example:

```bash
sudo ./quectel-mbim-proxy -d /dev/cdc-wdm0 &
sudo ./quectel-CM -s <apn1> -n 1 &
sudo ./quectel-CM -s <apn2> -n 2 &
```

If multi-PDN dial-up is not required, ignore this section.

## 12. Other Dial-Up Settings

Use `./quectel-CM -h` to view available options, and add the required parameters as needed.

```text
[07-09_19:38:35:319] QConnectManager_Linux_V1.6.8
[07-09_19:38:35:319] Usage: ./quectel-CM [options]
[07-09_19:38:35:319] -s [apn [user password auth]]          Set apn/user/password/auth get from your network provider. auth: 1~pap, 2~chap, 3~MsChapV2
[07-09_19:38:35:319] -p pincode                             Verify sim card pin if sim card is locked
[07-09_19:38:35:319] -p [quectel-][qmi|mbim]-proxy          Request to use proxy
[07-09_19:38:35:319] -f logfilename                         Save log message of this program to file
[07-09_19:38:35:319] -u usbmonlog filename                  Save usbmon log to file
[07-09_19:38:35:319] -i interface                           Specify which network interface to setup data call when multi-modems exits
[07-09_19:38:35:319] -4                                     Setup IPv4 data call (default)
[07-09_19:38:35:319] -6                                     Setup IPv6 data call
[07-09_19:38:35:319] -n pdn                                 Specify which pdn to setup data call (default 1 for QMI, 0 for MBIM)
[07-09_19:38:35:319] -k pdn                                 Specify which pdn to hangup data call (by send SIGINT to 'quectel-CM -n pdn')
[07-09_19:38:35:319] -m iface-idx                           Bind QMI data call to wwan0_<iface idx> when QMAP used. E.g '-n 7 -m 1' bind pdn-7 data call to wwan0_1
[07-09_19:38:35:319] -b                                     Enable network interface bridge function (default 0)
[07-09_19:38:35:319] -v                                     Verbose log mode, for debug purpose.
[07-09_19:38:35:319] -d                                     Obtain the IP address and dns through qmi
[07-09_19:38:35:319] -a                                     1:Device attempts to bring up a call with the APN name,if -a 1 need add -s apn_name ;2:Device attempts to bring up a call with the APN type,if -a 2 need add -y apn_type
[07-09_19:38:35:319] -y                                     Set APN type 0:APN type unspecified 1:internet traffic. 2:IMS
[07-09_19:38:35:319] [Examples]
[07-09_19:38:35:319] Example 1: ./quectel-CM
[07-09_19:38:35:319] Example 2: ./quectel-CM -s 3gnet
[07-09_19:38:35:319] Example 3: ./quectel-CM -s 3gnet carl 1234 1 -p 1234 -f gobinet_log.txt
```

## 13. Common Issues

### 13.1 `/dev/cdc-wdm0` Is Missing

Check:

```bash
ls -l /dev/cdc-wdm*
ls /sys/bus/usb/drivers | grep -E 'cdc_wdm|qmi_wwan|qmi_wwan_q|cdc_mbim'
dmesg | grep -iE 'cdc-wdm|qmi|mbim|2c7c'
```

Possible causes:

- The USB device is not enumerated correctly.
- The related driver is not loaded.
- The module is not powered on correctly or the USB connection is abnormal.
- The current system kernel does not include the corresponding driver support.

### 13.2 AT Port Is Missing

Check:

```bash
ls /dev/ttyUSB*
dmesg | grep -i ttyUSB
lsmod | grep option
```

The common AT port for this module is `/dev/ttyUSB2`. If other USB serial devices already exist in the system, the port number may change. Use the `dmesg` output as the reference.

### 13.3 SIM Is Not Ready

Check:

```text
AT+CPIN?
```

If `+CPIN: READY` is not returned, confirm:

- The SIM card is inserted correctly.
- The SIM card is not suspended or out of service.
- The SIM card does not require a PIN, or the PIN has been entered.
- The SIM card supports the current network type and operator network.

### 13.4 Network Registration Fails

Check:

```text
AT+COPS?
AT+CEREG?
AT+C5GREG?
AT+QENG="SERVINGCELL"
```

Recommended actions:

- Check the antenna connection.
- Move to another location and confirm whether 4G/5G signal coverage is available.
- Confirm that the SIM card operator matches the network available in the current area.
- Check signal quality. Very low RSRP or poor RSRQ may affect registration and dial-up.

### 13.5 Dial-Up Succeeds but Internet Access Fails

Check in order:

```bash
ip addr
ip route
ip route get 8.8.8.8
cat /etc/resolv.conf
ping -c 4 8.8.8.8
ping -c 4 www.baidu.com
```

Common causes:

- The module network interface did not obtain an IP address.
- The default route does not point to the module network interface.
- Multiple default routes exist in the system, and the priority is incorrect.
- DNS is not configured or unavailable.
- The APN is incorrect or the SIM card data service is abnormal.

### 13.6 Logs Required for Dial-Up Failure Analysis

Check the following information:

```bash
dmesg > dmesg.log
lsusb -t > lsusb-t.log
ip addr > ip-addr.log
ip route > ip-route.log
sudo ./quectel-CM -s cment -4 -v -f quectel-cm.log -u usbmon.log
```

Also check the following AT command results:

```text
ATI
AT+CPIN?
AT+COPS?
AT+CEREG?
AT+C5GREG?
AT+QENG="SERVINGCELL"
AT+CGDCONT?
```

## 14. Recommended Operation Procedure

The following steps apply to a single dial-up scenario using APN `cment`. Customers should replace the APN according to the actual SIM card.

```bash
echo "1. Check device nodes."
ls -l /dev/cdc-wdm0 /dev/ttyUSB2

echo "2. Check drivers."
ls /sys/bus/usb/drivers | grep -E 'option|cdc_wdm|qmi_wwan|qmi_wwan_q|cdc_mbim'

echo "3. Check network interfaces."
ip link

echo "4. Start dial-up."
sudo ./quectel-CM -s cment -4 &

echo "5. Check IP addresses, routes, and DNS."
ip addr
ip route
cat /etc/resolv.conf

echo "6. Test the network."
ping -c 4 8.8.8.8
ping -c 4 www.baidu.com
```

