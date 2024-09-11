# Contents

- [Contents](#contents)
- [Download ISO image](#download-iso-image)
- [Build the file system](#build-the-file-system)
- [Download the necessary installation packages](#download-the-necessary-installation-packages)
- [Disable unnecessary services](#disable-unnecessary-services)

# Download ISO image

[Ubuntu Server for ARM](https://ubuntu.com/download/server/arm)

 > *Guaranteed to be Ubuntu **server arm64**  version*

- **Download this ISO image to your Linux system**

  For example, "ubuntu-24.04-live-server-arm64.iso"

# Build the file system
- **Mount the image to Linux:**
    ```shell
    sudo mkdir -p /mnt/iso
    sudo mount -o loop ubuntu-24.04-live-server-arm64.iso /mnt/iso/
    ```
- **Write the file system to `/tmp/rootfs`:**
    ```shell
    sudo unsquashfs -d /tmp/rootfs /mnt/iso/casper/ubuntu-server-minimal.squashfs
    ```
- **Ensure the file system is decrypted before proceeding.**

  To modify the `/etc/passwd` file in `/tmp/rootfs`, follow these steps:

1. Open the file with `vi`:
    ```bash
    sudo vi /tmp/rootfs/etc/passwd
    ```

2. Find the line:
    ```plaintext
    root:x:0:0:root:/root:/bin/bash
    ```

3. Change it to:
    ```plaintext
    root::0:0:root:/root:/bin/bash
    ```

4. Save and exit `vi` by pressing `Esc`, then typing `:wq`, and pressing `Enter`.

- **Port the SDK compilation contents:**
1. Decompress the SDK BusyBox root file system:
    ```shell
    mkdir -p /tmp/rootfs-busybox-original
    sudo tar -xvf sdk_busybox_rootfs.tar -C /tmp/rootfs-busybox-original
    ```
2. Copy SDK plugins to the specified location:
    ```shell
    sudo mkdir /tmp/rootfs/lib/modules /tmp/rootfs/lib/firmware
    sudo cp -rp /tmp/rootfs-busybox-original/boot/Image /tmp/rootfs/boot/
    sudo cp -rp /tmp/rootfs-busybox-original/lib/firmware/* /tmp/rootfs/lib/firmware/
    sudo cp -rp /tmp/rootfs-busybox-original/lib/modules/* /tmp/rootfs/lib/modules/
    sudo cp -rp /tmp/rootfs-busybox-original/lib/modules/* /tmp/rootfs/lib/modules-load.d/
    ```
- **Compress the organized root file system:**
  ```shell
  sudo tar -czvf ~/rootfs-ubuntu24-min.tar.gz -C /tmp/rootfs .
  ```

# Download the necessary installation packages
- **Install `qemu-user-static:**

1. Install `qemu-user-static` on the host machine:
   ```bash
   sudo apt-get install qemu-user-static
   ```

2. Copy `qemu-aarch64-static` to the target file system:
   ```bash
   sudo cp /usr/bin/qemu-aarch64-static /tmp/rootfs/usr/bin/
   ```

3. Copy the `resolv.conf` file to the target file system:
   ```bash
   sudo cp -b /etc/resolv.conf /tmp/rootfs/etc/
   ```

- **Mount Ubuntu OS:**
    ```shell
    chmod +x ch-mount.sh
    ./ch-mount.sh -m /tmp/rootfs/
    ```
    ```shell
    #!/bin/bash

    # ch-mount.sh
    function mnt() {
        echo "MOUNTING"
        sudo mount -t proc /proc ${2}proc
        sudo mount -t sysfs /sys ${2}sys
        sudo mount -o bind /dev ${2}dev
        sudo mount -o bind /dev/pts ${2}dev/pts     
        sudo chroot ${2}
    }

    function umnt() {
        echo "UNMOUNTING"
        sudo umount ${2}proc
        sudo umount ${2}sys
        sudo umount ${2}dev/pts
        sudo umount ${2}dev
    }

    if [ "$1" == "-m" ] && [ -n "$2" ] ;
    then
        mnt $1 $2
    elif [ "$1" == "-u" ] && [ -n "$2" ];
    then
        umnt $1 $2
    else
        echo ""
        echo "Either 1'st, 2'nd or both parameters were missing"
        echo ""
        echo "1'st parameter can be one of these: -m(mount) OR -u(umount)"
        echo "2'nd parameter is the full path of rootfs directory(with trailing '/')"
        echo ""
        echo "For example: ch-mount -m /media/sdcard/"
        echo ""
        echo 1st parameter : ${1}
        echo 2nd parameter : ${2}
    fi
    ```

- **Download the necessary software packages:**
  
  ```shell
  sudo apt install ca-certificates \
  language-pack-en-base \
  software-properties-common \
  ssh \
  net-tools \
  iputils-ping \
  bash-completion \
  openssh-server \
  vim \
  u-boot-tools \
  curl \
  ethtool \
  mtd-utils \
  pciutils \
  netplan.io \
  network-manager \
  gcc \
  make \
  lm-sensors \
  kmod \
  i2c-tools
  ```
- **Enable Serial Port Services:**

    ```bash
    systemctl enable serial-getty@ttyAMA0.service
    systemctl disable serial-getty@ttyS0.service
    systemctl disable getty@tty1.service
    ```

- **Modify Default Shell:**

    ```bash
    ln -sf /bin/bash /bin/sh
    ```
- **Umount**
    ```bash
    exit
    ./ch-mount.sh -u /tmp/rootfs/
    ```
# Disable unnecessary services
- **Reduce the startup time for `systemd-networkd-wait-online.service`:**
  ```bash
  sudo systemctl disable cloud-init
  sudo systemctl stop cloud-init
  sudo apt-get remove --purge cloud-init
  ```

- **Disable `cloud-init` and shorten the startup time:**
  ```bash
  sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d/
  sudo nano /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf
  ```

- **In the `override.conf` file, add the following content to set the timeout (e.g., set the timeout to 10 seconds):**
  ```plaintext
  [Service]
  TimeoutStartSec=10s
  ```