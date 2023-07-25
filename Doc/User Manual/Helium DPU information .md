# Get DPU information



___






## Get system information
#### command：
```
	 #python3 /usr/local/Helium/get_cpuinfo.py 
```
#### result:

```
			System Version:         Debian GNU/Linux 10 (bookworm)
			Kernal Version:         4.14.76-10.3.4.0-4
			OvS Version:            ovs-vswitchd (Open vSwitch) 3.1.2
			Uboot Version:          U-Boot 2020.10-6.0.0 (Jun 29 2023 - 16:11:42 +0800)
			RCLK:                   1800Mhz
			SCLK:                   1200Mhz
			CPT-CLK:                1000Mhz
			CPU Temperature:        56.25
			Memory Size:            31GiB
			EMMC Size:              57.62GiB
			Product Name:           EC2002P(OR EC2004Y)
			Part Number:            EC2002P(OR EC2004Y)
			Serial Number:          F302318A001
			Base MAC Address:       60:EB:5A:11:22:33
			Manufacture Date:       17/07/2021 23:59:59
			Device Version:         1
			Label Revision:         0
			Platform Name:          x86_64-af_ec96_4y-r0
			Loader Version:         X
			MAC Addresses:          1
			Manufacturer:           Asterfusion
			Country Code:           CN
			Vendor Name:            Asterfusion
			Main Board Informat:    read
			Architecture:           aarch64
			CPU op-mode(s):         64-bit
			Byte Order::            Little Endian
			CPU(s):                 24
			On-line CPU(s) list:    0-23
			Vendor ID:              Cavium
			Model:                  name:
			Model:                  1
			Thread(s) per core:     1
			Socket(s):              -
			Stepping:               0x2
			BogoMIPS:               200.00
			Flags:                  fp asimd aes pmull sha1 sha2 crc32 atomics cpuid asimdrdm dcpop L1d cache:              984KiB
			L1i cache:              1.5MiB
			L2i cache:              5MiB
			L3 cache:               14MiB
			NUMA node(s):           1
			CPU(s):                 node0

```


##	Get core temperature temperature
#### command：
```
	#txcsr tsnx_ts_temp_conv_result -a 0 -x
```
#### result:
```
	
Value of tsnx_ts_temp_conv_result [0x000087e0c0000068] :[0x00000000008ee8e0]

Register : TSNX_TS_TEMP_CONV_RESULT
 [63:24] RESERVED_24_63       =          0 (0x0)
  [   23] N_VALID              =          1 (0x1)
  [22:12] N_VALUE              =        238 (0xee)
  [   11] TEMP_VALID           =          1 (0x1)
  [10: 0] TEMP_CORRECTED       =        224 (0xe0)

```
#### explanation:
Since the temperature is calibrated,TEMP_CORRECTED needs to be divided by 4 to obtain the actual value.
example:
	TEMP_CORRECTED=224
	actual value is 224/4=56℃
#####  Due to the presence of 11 internal registers, it is necessary to read them all to obtain the highest value.
commands:
```
	#txcsr tsnx_ts_temp_conv_result -a 1 -x
	#txcsr tsnx_ts_temp_conv_result -a 2 -x
	#txcsr tsnx_ts_temp_conv_result -a 3 -x
	#txcsr tsnx_ts_temp_conv_result -a 4 -x
	#txcsr tsnx_ts_temp_conv_result -a 5 -x
	#txcsr tsnx_ts_temp_conv_result -a 6 -x
	#txcsr tsnx_ts_temp_conv_result -a 7 -x
	#txcsr tsnx_ts_temp_conv_result -a 8 -x
	#txcsr tsnx_ts_temp_conv_result -a 9 -x
	#txcsr tsnx_ts_temp_conv_result -a 10 -x
```	
	






## Get module temperature
#### command(on EC2002p)：
```
	#12cdump -f -y 1 0x50
	#12cdump -f -y 0 0x50
```
#### result
```
	     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    	0123456789abcdef
		00: 4b 00 fb 00 46 00 00 00 88 b8 78 50 87 f0 79 18    K.?.F...??xP??y?
		10: 19 64 00 fa 15 2d 01 f4 62 1f 0f 8d 57 73 13 94    ?d.??|??b???Ws??
		20: 3d e9 04 eb 37 2d 05 85 00 00 00 00 00 00 00 00    =???7-??........
		30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
		40: 00 00 00 00 3f 80 00 00 00 00 00 00 01 00 00 00    ....??......?...
		50: 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 ed    ?...?...?......?
		60: 2e be 81 b8 08 fc 1d ac 13 88 00 00 00 00 00 00    .?????????......
		70: 00 00 00 00 00 00 00 00 ff ff ff 00 00 00 00 00    ................
		80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		90: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		a0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		b0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		c0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		d0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		e0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
		f0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	
```
Temperature can be read from the 21st and 22nd digits which is 0x2d and 0x01, actual value is 45.1℃(According to hexadecimal,0x2d=45,0x01=1 ).Read temperatures of multiple modules sequentially using commands.
	
#### command(on EC2004y):
```
	#i2cdump -f -y 0 0x51
	#i2cdump -f -y 1 0x51
	#i2cdump -f -y 2 0x51
	#i2cdump -f -y 3 0x51
```
#### result:
```
	     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
	00: 4b 00 fb 00 46 00 00 00 88 b8 78 50 87 f0 79 18    K.?.F...??xP??y?
	10: 19 64 00 fa 15 7c 01 f4 62 1f 0f 8d 57 73 13 94    ?d.??|??b???Ws??
	20: 3d e9 04 eb 37 2d 05 85 00 00 00 00 00 00 00 00    =???7-??........
	30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................
	40: 00 00 00 00 3f 80 00 00 00 00 00 00 01 00 00 00    ....??......?...
	50: 01 00 00 00 01 00 00 00 01 00 00 00 00 00 00 ed    ?...?...?......?
	60: 2f 28 81 bb 08 fc 1d ac 13 6e 00 00 00 00 00 00    /(???????n......
	70: 00 00 00 00 00 00 00 00 ff ff ff 00 00 00 00 00    ................
	80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	90: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	a0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	b0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	c0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	d0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	e0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
	f0: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff    ................
```	
Temperature can be read from the 49th and 50th digits which is 0x2f and 0x28, actual value is 47.40℃(According to hexadecimal,0x2f=47,0x28=40).Read temperatures of multiple modules sequentially using commands.

	


