MODULE_MAME = mgmt_net
PCIE_HOST ?= $(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/src/host/linux/kernel/drv
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
 
SRCS = host_ethdev.c 
 
INCLUDE_DIR = -I$(src) -I$(PCIE_HOST) -I$(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/inc \
			  -I$(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/src/common/ \
			  -I$(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/src/host/osi \
			  -I$(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/src/host/osi/octvf 
 
ccflags-y := $(INCLUDE_DIR)
KBUILD_EXTRA_SYMBOLS := $(PCIE_HOST)/Module.symvers
 
OBJS =  $(SRCS:.c=.o)

obj-m += $(MODULE_MAME).o
$(MODULE_MAME)-y = $(OBJS)
 
GCC_VER := $(shell echo `gcc -dumpversion | cut -f1-2 -d.` \>= 9 | bc )
ifeq ($(GCC_VER),1)
ccflags-y += -Wno-missing-attributes -fno-optimize-sibling-calls
endif

# path for kernel version changes
#
#
PATCH_STR:=$(shell cat $(OCTEONTX_HOST_ROOT)/$(PATCHDIRS)/$(PATCH_FILE))
ifeq ($(findstring P_SKBUFF_XMIT_MORE_2,$(PATCH_STR)), P_SKBUFF_XMIT_MORE_2)
ccflags-y += -DP_SKBUFF_XMIT_MORE_2
endif
#
#


all:
	echo make -c $(KERNEL_DIR) M=`pwd` modules
	make -C $(KERNEL_DIR) M=`pwd` modules 
 
clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
