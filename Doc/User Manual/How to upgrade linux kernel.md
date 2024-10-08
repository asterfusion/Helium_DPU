# How to upgrade linux kernel to upstream
The upstream version is in the yocto git repository, you can follow the steps to upgrade to new version.

## 1.Clone the code and config
```shell
git clone -b 'v6.6/standard/cn-sdkv6.1/octeon' 'https://git.yoctoproject.org/linux-yocto'
```
copy [linux.config](../../ET2500/Platform/linux.config) to linux-yocto
```shell
cp linux.config linux-yocto/.config
```
## 2.Make and Install
```shell
make bindeb-pkg
```
After sucess, the deb pkg is put in the upper directory.
Then you can install the linux-image-.*.deb, the kernel image will be in the /boot/ directory.
```shell
dpkg -i linux-image*.deb
```

## 3.Update uboot env for next boot
Use fw_setenv to change the bootcmd, for example:
```shell
fw_setenv bootcmd 'ext4load mmc 0:1 $bootloadaddr boot/vmlinuz-6.6.54-01126-g52e28631fc43;booti $loadaddr - $fdtcontroladdr'
```
After success, reboot the device.
