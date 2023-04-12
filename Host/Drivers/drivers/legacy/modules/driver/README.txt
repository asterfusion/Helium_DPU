

               CNNIC-SDK: Linux PCI-e Driver for Cavium NIC Processors
               =======================================================

 Contents:
 ---------
    I. Installing and applying patches
   II. Compiling OCTEONTX Linux kernel with embedded initramfs
  III. a. Compiling the CNNIC-SDK-SRC sources
       b. Compiling the CNNIC Firmware applications
   IV. Preparing USB device to Boot Linux on OCTEONTX
    V. Booting the CNNIC Application
   VI. Host utilities and test applications.
  VII. Limitations
 VIII. Known issues


 I. Installing and applying patches
 ----------------------------------
   Please ensure that the following pre-requisites are met prior to 
   installation.

   The CNNIC-SDK-SRC-6.2.0-XX.x86_64.rpm requires the following:
     o OCTEONTX-SDK-6.2.0-build26.x86_64.rpm with patch_release#2.
     o OCTEONTX-SE2-6.2.0-build31.x86_64.rpm with patch_release#2.

   1. Installing CNNIC-SDK-SRC-6.2.0-XX.x86_64.rpm RPM:
   ----------------------------------------------------
     The following command can be used to install the CNNIC-SDK-SRC RPM, where
     XX refers to the build number:

      # rpm -ivh CNNIC-SDK-SRC-6.2.0-XX.x86_64.rpm

     The CNNIC-SDK-SRC will be installed by default at:
       /usr/local/Cavium_Networks/CNNIC-SDK-SRC

     Rest of the README instructions assumes that the OCTEONTX-SDK and
     CNNIC-SDK-SRC packages are installed at the default location:
       /usr/local/Cavium_Networks/

 NOTE: This Pre-release supports only OCTEONTX CN83XX.

   2. Applying Patches:
   --------------------
     For CNNIC-SDK-SRC to work, following two patches located at
       /usr/local/Cavium_Networks/CNNIC-SDK-SRC/patches/
     need to be applied

       a. sdk patch     : CNNIC-SDK-SRC-6.2.0-octeontx-sdk620-p2.patch
       b. se2 patch     : CNNIC-SDK-SRC-6.2.0-octeontx-se2-620-p2.patch

   To apply the patches, follow the below steps:

     1. Change directory to THUNDER_ROOT
         # cd /usr/local/Cavium_Networks/OCTEONTX-SDK

     2. Apply the patches 'a' and 'b'
        a. Apply sdk patch:
        # patch -s -p1 < CNNIC-SDK-SRC-6.2.0-octeontx-sdk620-p2.patch

        b. Apply se2 patch:
        # patch -s -p1 < CNNIC-SDK-SRC-6.2.0-octeontx-se2-620-p2.patch
        
 II. Compiling OCTEONTX Linux kernel with embedded initramfs
 -----------------------------------------------------------
   1. Set up OCTEONTX-SDK environment.
       # cd /usr/local/Cavium_Networks/OCTEONTX-SDK/
       # source env-setup

   2. Modify kernel configuration options
       # cd $THUNDER_ROOT/linux/kernel/linux
       # cp $THUNDER_ROOT/linux/kernel/kernel.config .config
       # make menuconfig ARCH=arm64
   
      To use OCTEONTX pf drivers, be sure to enable the following kernel
      configuration options:

      # 64K pages enabled
      CONFIG_ARM64_64K_PAGES=y
      CONFIG_ARM64_VA_BITS_48=y
      # hugepages support enabled
      CONFIG_HUGETLBFS=y
      CONFIG_HUGETLB_PAGE=y
      # VFIO enabled with TYPE1 IOMMU at minimum
      CONFIG_VFIO_IOMMU_TYPE1=y
      CONFIG_VFIO_VIRQFD=y
      CONFIG_VFIO=y
      CONFIG_VFIO_NOIOMMU=y
      CONFIG_VFIO_PCI=y
      CONFIG_VFIO_PCI_MMAP=y
      # OCTEONTX specific ECAM support enabled
      CONFIG_PCI_HOST_OCTEONTX_ECAM=y
      # OCTEONTX co-processors drivers
      CONFIG_OCTEONTX_FPA_PF=y
      CONFIG_OCTEONTX_FPA_VF=y
      CONFIG_OCTEONTX_SSO_PF=y
      CONFIG_OCTEONTX_SSOW_PF=y
      CONFIG_OCTEONTX_PKO_PF=y
      CONFIG_OCTEONTX_TIM_PF=y
      CONFIG_OCTEONTX_PKI=y
      CONFIG_OCTEONTX_LBK=y
      CONFIG_OCTEONTX_RST=y
      CONFIG_OCTEONTX_DPI=y
      CONFIG_OCTEONTX_SLI_PF=y
      CONFIG_OCTEONTX_ZIP=y
      CONFIG_CRYPTO_DEV_CPT=y
      CONFIG_OCTEONTX=y

   3. To compile the Linux kernel with embedded initramfs.
       # cd $THUNDER_ROOT
       # make linux-kernel-minimal
       # make cavium-initramfs
       # make linux-kernel-minimal INITRAMFS=y

   The Linux kernel binary image("Image") will be created under the
   $THUNDER_ROOT/linux/kernel/linux/arch/arm64/boot directory.
   
   4. Re-compile the u-boot image
       # cd $THUNDER_ROOT
       # make uboot-build PLAT=t83

   The U-boot binary image("thunder-bootfs-uboot-t83.img") will be
   created under the $THUNDER_ROOT/target/images/ directory.

 NOTE: Follow the standard OCTEONTX SDK kernel build procedure to 
 build kernel with rootfs

 III. a. Compiling the CNNIC-SDK-SRC Sources
 -------------------------------------------
   1. Compile CNNIC-SDK-SRC sources.
      NOTE: By default host driver is configured for NIC mode operation.
            For Base mode operation, disable "OCT_NIC_USE_NAPI" and 
            "OCT_REUSE_RX_BUFS" features in 
               $CNNIC_ROOT/modules/driver/src/driver.mk file.

       # cd /usr/local/Cavium_Networks/CNNIC-SDK-SRC/
       # source nic-env-setup.sh
       # cd modules/driver/src
       # make

   This will compile base, nic drivers. Host driver binaries symbolic links 
   are created at:
     $CNNIC_ROOT/modules/driver/bin directory.

 III. b. Compiling the CNNIC Firmware applications
 -------------------------------------------------
   To build OCTEONTX ODP with default configurations:
     # cd /usr/local/Cavium_Networks/OCTEONTX-SDK/SE2/odp/
     # ./platform/linux-octeontx/scripts/odp-build.sh

   The steps will compile the CNNIC firmware applications also.

   NIC application "odp_cnnic_nic" binary will be available at
     $ODP_ROOT/example/cnnic/nic/

   BASE application "odp_cnnic_base" binary will be available at
     $ODP_ROOT/example/cnnic/base/

 Follow the section "Building OcteonTX ODP" in octtx-odp-user-guide.txt
 for more build and configure options.
 The document is present in below path:
     $ODP_ROOT/platform/linux-octeontx/doc

 IV. Preparing USB device to Boot Linux on OCTEONTX
 --------------------------------------------------
   Attach a USB device to the Host in which CNNIC-SDK-SRC is compiled.
   Please check "fdisk -l" for the USB device connected to the Host system,
   assume that the USB device is populated as /dev/sdX

   NOTE: the below steps assumes that USB device is detected as /dev/sdX

   1. On the Host machine, execute the "create_disk.sh" script; 
      this script helps in partitioning and formatting the disk.
       # cd $THUNDER_ROOT
       # ./host/bin/create_disk.sh --raw-disk /dev/sdX

   NOTE: Make sure the attached disk is not auto mounted.

   2. Copy the kernel image to the second partition as follows:
       # mkdir -p /mnt/disk2
       # mount /dev/sdX2 /mnt/disk2    /* mount 2nd partition of disk */
       # cd $THUNDER_ROOT/linux/kernel/linux/arch/arm64/boot
       # cp Image /mnt/disk2/.
       # sync

   3. Copy CNNIC application binary and other scripts to /app directory.
       # cd $ODP_ROOT
       # mkdir -p /mnt/disk2/app
       # cp -r platform/linux-octeontx/scripts/  /mnt/disk2/app/.
       # cp example/cnnic/nic/odp_cnnic_nic  /mnt/disk2/app/.
       # cp example/cnnic/nic/set_nic_env.sh  /mnt/disk2/app/.
       # cp example/cnnic/base/odp_cnnic_base  /mnt/disk2/app/.
       # cp example/cnnic/base/set_base_env.sh  /mnt/disk2/app/.
       # sync

   4. Unmount.
       # umount /mnt/disk2

   This completes the copying of kernel image and CNNIC application to 
   the attached disk.

   NOTE: Make sure /dev/sdX1 and /dev/sdX2 are not auto mounted.

   The above 4 steps are only required initially for preparing the USB device,
   Later on to test any nic/base firmware related changes, follow the below 
   steps.

   1. Rebuild the CNNIC code using the above CNNIC-SDK-SRC source compilation 
      and Firmware compilation steps.
   2. Remove the USB device from EBB and plug into the host machine. 
   3. Find the mount point of the USB device on host and copy base application 
      binary into USB device's 2nd partition <mount point>/app/ directory.
       #cd $ODP_ROOT
       #cp example/cnnic/base/odp_cnnic_base  <mount point>/app/.
       #sync


 V. Booting the CNNIC Application
 --------------------------------
   1. Plug in the USB drive to CN83XX EBB board.

   2. Detach CN83XX pcie device from pci bus on host machine.
       # echo 1 >> /sys/bus/pci/devices/<BDF>/remove

   3. To update the re-compiled uboot image, copy the 
      "thunder-bootfs-uboot-t83.img" into the Host "tftpboot" folder 
      and start the TFTP server.

   4. In the MCU console, configure tftp server ip and set the environment 
      variable "octimagename" that matches with the firmware image name and 
      use the below MCU command to update the firmware image. 
      This will overwrite the default firmware image on the board 
      with "thunder-bootfs-uboot-t83.img".
       # thunder_update -p

   5. Perform a PCI bus rescan on host side.
       # echo 1 >> /sys/bus/pci/rescan

   Ensure that CN83XX pcie device is rescanned and shows up in the "lspci".

   6. Load octeon_drv.ko module on host and create the device file.
       # cd $CNNIC_ROOT/modules/driver/bin/
       # insmod octeon_drv.ko
       # mknod /dev/octeon_device c 127 0

   U-boot will start booting on CN83XX. Wait till u-boot command prompt 
   comes up. Set below kernel boot argument from u-boot prompt.

   7. Load kernel image from USB
       EBB8304> usb start
       EBB8304> usb storage /* This displays <device> number */
       EBB8304> ext4load usb <device>:2 $kernel_addr Image
       EBB8304> booti $kernel_addr - $fdtcontroladdr

   NOTE: The usb storage command displays the device number; replace
   <device> in the above commands accordingly.

   8. Once kernel is booted up on 83xx EBB, issue below commands on command
      prompt to start the CNNIC application.
       # mount -t devtmpfs none /dev
   NOTE: Above command is only required if the devtmpfs is not mounted.

       # mount /dev/sda2 /mnt/
       # cd /mnt/app/

      A. For running NIC application:
       # source set_nic_env.sh <domain_name>
       # ODP_DOMAIN_ID=`./scripts/odp-domain-id.sh <domain_name>`
       # ./odp_cnnic_nic -d $ODP_DOMAIN_ID

      B. For running BASE application:
       # source set_base_env.sh <domain_name>
       # ODP_DOMAIN_ID=`./scripts/odp-domain-id.sh <domain_name>`
       # ./odp_cnnic_base -d $ODP_DOMAIN_ID

   9. Load the octnic.ko NIC driver module on the host
   NOTE: This step is applicable only for NIC mode of operations.

      Wait until nic application initialization completes before loading the
      NIC driver module on host.

      Now load the octnic module:
       # insmod octnic.ko

  NOTE: If "received IRERR_RINT intr" message is observed on host dmesg log
  during steps #8 or #9, please unload the host driver and redo all the
  steps starting from #6.

 VI. Host utilities and test applications
 ----------------------------------------
   The PCI base driver package includes the following host side utilities and
   test applications that can be run on the host system:
        1. oct_stats utility
        2. req_resp kernel-space test application
        3. droq_test kernel-space test application
        4. oct_req user-space test application

   The PCI base driver package includes oct_stats that can be run on the host
   system to get status information. The sources can be found at
   $CNNIC_ROOT/modules/driver/src/host/linux/user/utils. The user api library
   must be created before the utilities can be compiled.

   To compile the user-space API, you can do a

     o "make host_api" at $CNNIC_ROOT/modules/driver/src OR
     o "make" at $CNNIC_ROOT/modules/driver/src/host/linux/user/api

   To compile the utility sources, you can do a

     o "make utils" at $CNNIC_ROOT/modules/driver/src OR
     o "make" at $CNNIC_ROOT/modules/driver/src/host/linux/user/utils


   1. oct_stats (OCTEON statistics display utility) - oct_stats allows the
   user to check on the input, output and DMA queue statistics for packet
   count and byte count. It also displays 10-second average byte count for
   input and output queues. "oct_stats -h" displays information about
   usage and available options. 

   The PCI base driver package includes sample programs to demonstrate usage
   of the input and output queues and the PCI DMA engines of OCTEON using the
   PCI driver.

   To compile the test application sources, you can do a
     o "make tests" at $CNNIC_ROOT/modules/driver/src

   The following kernel-space applications are available:

   2. req_resp - Provides a linux kernel module that uses the API's exported
   by the driver for request processing to send requests to the OCTEON
   cores. It requires the cvmcs core application to respond to the
   requests it sends.

   3. droq_test - Provides a linux kernel module that registers dispatch
   functions for a set of pre-defined opcodes. It requires the cvmcs core
   application to send packets on the PCI output queues with these opcodes.

 NOTE: Enable the CVMCS_TEST_PKO macro in 
        ODP_ROOT/example/cnnic/base/cvmcs-test.h to send test packets on 
      the output queues with opcodes DROQ_PKT_OP1 and DROQ_PKT_OP2.
      You need to follow the steps specified in the last section of
      the chapter "IV. Preparing USB device to Boot Linux on OCTEONTX"
      for testing firmware related changes.

   There is also a user-space application:

   4. oct_req - It uses the user api's from the host api library to send
   requests to the OCTEON cores. It requires the cvmcs core application
   to respond to the requests it sends. "oct_req -h" displays information
   about usage and available options.


 VII. Limitations
 ----------------
 This Pre-release supports OCTEONTX CN83XX with below limitations
   1. PCI-e EP mode PF domain operation is only supported, verified
      using QLM#0 and QLM#1.
   2. Single NIC interface XAUI/XLAUI mode is supported on QLM#2.
   3. Only eight SDP queues(Queue #0 to Queue #7) are supported.
   4. Mac address and MTU size change are not supported.
   5. TSO is not supported.
   6. EtherPCI mode of operation is not supported.
   7. This release is only verified on SL-7.3 and CentOS-7.3 host OS.
   8. Multi-card setup is not supported.

 VIII. Known issues
 ------------------
   1. Long run iperf Tx(client) tests are not stable.
   2. Kernel req_resp: IQ[X] is full message observed with some combinations
      of gather, scatter and scatter_gather mode requests.

< EOF >
