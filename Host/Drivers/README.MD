# How to Compile Host Drivers

___

### 1.Drivers for sdk10
```
	cd Helium_DPU/Host/Drivers/drivers_for_SDK10
	make
```
The .ko files are located in the Helium_DPU/Host/Drivers/drivers_for_SDK10 directory.
The operating systems for sdk10 we have tested are as follows:
- CentOS7.9/CentOS8.5
- Ubuntu18.04/Ubuntu20.04
- 中科方德nfs4.0
- 统信uos
- 银河麒麟高级服务器操作系统 V10

if use uos and kernel version <5.0, use  
```
git apply patch_for_uos
```


### 2.Drivers for sdk11
```
	cd Helium_DPU/Host/Drivers/drivers_for_SDK11
	make
```
The .ko files are located in the Helium_DPU/Host/Drivers/drivers_for_SDK11 directory.
### 3.Drivers for sdk12
```
	cd Helium_DPU/Host/Drivers/drivers_for_SDK12
	make
```
The .ko files are located in the Helium_DPU/Host/Drivers/drivers_for_SDK12 directory.



