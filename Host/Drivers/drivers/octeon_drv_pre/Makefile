
#MODULE_MAME = octeon_drv_pre
obj-m += octeon_drv_pre.o

all:
	echo make -C /lib/modules/$(shell uname -r)/build M=`pwd` module
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` modules


clean:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd` clean