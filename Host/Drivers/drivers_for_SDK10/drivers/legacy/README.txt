Instructions to Build and Load pcie_host driver
===============================================
1. Build base and nic kernel modules
   # cd pcie_host/modules/driver/src
   # make

   This will generate .ko files under pcie_host/modules/driver/bin/.

2. Cleanup the build
   # cd modules/driver/src
   # make all_clean

3. Load newly built module
   # cd pcie_host/modules/driver/bin/
   # insmod octeon_drv.ko
   # insmod octnic.ko

