#
#
# CNNIC SDK
#
# Copyright (c) 2018 Cavium Networks. All rights reserved.
#
# This file, which is part of the CNNIC SDK which also includes the
# CNNIC SDK Package from Cavium Networks, contains proprietary and
# confidential information of Cavium Networks and in some cases its
# suppliers. 
#
# Any licensed reproduction, distribution, modification, or other use of
# this file or the confidential information or patented inventions
# embodied in this file is subject to your license agreement with Cavium
# Networks. Unless you and Cavium Networks have agreed otherwise in
# writing, the applicable license terms "OCTEON SDK License Type 5" can be
# found under the directory: $CNNIC_ROOT/licenses/
#
# All other use and disclosure is prohibited.
#
# Contact Cavium Networks at info@caviumnetworks.com for more information.
#
################################################################################


#
# Makefile for Linux Octeon PCI driver
#


#
# Compilation Flags.
# Select one or more attributes for the driver from the list below. 
#
#  COMPILEFOR = DEBUG ETHERPCI
#
COMPILEFOR= 



#
# Setup path to sources and linux version
#

# Give the complete path to driver.mk here.
# Modify path if required.
ifdef CNNIC_ROOT
include $(CNNIC_ROOT)/modules/driver/src/driver.mk
endif



#
# Setup compilation flags here
#
WARNINGS = -Wall -Werror -Wuninitialized -Wunused-function -Werror-implicit-function-declaration 

#Disable warnings realted to __DATE__  and __TIME__, if the gcc version greather than 4.8
GCC_VER := $(shell echo `gcc -dumpversion | cut -f1-2 -d.` \>= 4.9 | bc )
ifeq ($(GCC_VER),1)
WARNINGS += -Wno-error=date-time -Wno-date-time
endif


#Disable warnings [stringop-truncation | stringop-overflow ...] 
# if the gcc version greather than 8
GCC_VER := $(shell echo `gcc -dumpversion | cut -f1-2 -d.` \>= 8 | bc )
ifeq ($(GCC_VER),1)
WARNINGS += -Wno-error=stringop-truncation -Wno-stringop-truncation
WARNINGS += -Wno-error=stringop-overflow -Wno-stringop-overflow
WARNINGS += -Wno-error=missing-attributes -Wno-missing-attributes 
WARNINGS += -Wno-error=incompatible-pointer-types -Wno-incompatible-pointer-types 
WARNINGS += -Wno-error=restrict -Wno-restrict 
WARNINGS += -Wno-implicit-fallthrough
#WARNINGS += -fno-optimize-sibling-calls
endif


KERNEL_VER := $(shell echo `uname -r |cut -d'.' -f1-2` \>= 5.0|bc )
MAKEKERNEL := $(MAKE) -C $(kernel_source) SUBDIRS=`pwd`  modules; 
ifeq ($(KERNEL_VER), 1)
WARNINGS +=  -Wno-error=implicit-fallthrough= -Wno-error=declaration-after-statement
SUBDIRS ?= $(shell pwd)
endif

INCLUDE += -I. -I$(SUBDIRS)/../../../../common    -I$(SUBDIRS)/../../../osi    \
	-I$(SUBDIRS)/../../../osi/octvf	\
	-I$(SUBDIRS)/../../../../../inc  -I$(SUBDIRS)/../test -I$(SUBDIRS)

EXTRA_CFLAGS +=	-D__SMP__ -O2 -finline-functions $(INCLUDE) $(WARNINGS)

#EXTRA_CFLAGS += -DFAST_PATH_DROQ_DISPATCH

EXTRA_CFLAGS += ${OCTDRVFLAGS}

ifeq ($(KERNEL_VER), 1)
MAKEKERNEL := $(MAKE) -C $(kernel_source) M=`pwd` EXTRA_CFLAGS='${EXTRA_CFLAGS}'  modules; 
endif
#
# Driver object files
#
default: check_cnnic all 

check_cnnic:
ifndef CNNIC_ROOT
	@echo "####################################################"
	@echo "              CNNIC_ROOT not defined"     
	@echo " Run the nic-env-setup.sh script in the CNNIC root directory"
	@echo "####################################################"
	@exit 2
endif

OBJS += octeon_linux.o            	\
        octeon_main.o             	\
	octeon_poll.o             		\
	octeon_ioctl.o            		\
	cavium_proc.o             		\
	facility.o             		\
	device_access.o			\
	../../../osi/request_manager.o  \
	../../../osi/octeon_iq.o  	\
	../../../osi/response_manager.o \
	../../../osi/pending_list.o     \
	../../../osi/octeon_device.o    \
	../../../osi/cn83xx_pf_device.o    \
	../../../osi/cn83xx_common.o    \
	../../../osi/cn93xx_pf_device.o    \
	../../../osi/cn93xx_common.o    \
	../../../osi/octeon_errata.o    \
	../../../osi/octeon_mem_ops.o   \
	../../../osi/octeon_droq.o      \
	../../../osi/octeon_mailbox.o

ifeq ($(findstring DEBUG,$(COMPILEFOR)), DEBUG)
# Creates debug levels.
# The default debug level is 0 when only critical messages are printed.
# Only errors are printed if this flag is not defined.
EXTRA_CFLAGS += -DCAVIUM_DEBUG=0
OBJS += ../../../osi/octeon_debug.o
endif


ifeq ($(findstring BUFPOOL,$(COMPILEFOR)), BUFPOOL)
# Enable this flag to use preallocated buffer pools for dynamic memory
# allocation.
EXTRA_CFLAGS += -DUSE_BUFFER_POOL
OBJS += ../../../osi/buffer_pool.o
endif


ifeq ($(findstring ETHERPCI,$(COMPILEFOR)), ETHERPCI)
# For Ethernet over PCI
EXTRA_CFLAGS += -DETHERPCI
EXTRA_CFLAGS := $(filter-out -DOCT_NIC_USE_NAPI, $(EXTRA_CFLAGS)) 
EXTRA_CFLAGS := $(filter-out -DOCT_REUSE_RX_BUFS, $(EXTRA_CFLAGS)) 
endif

# path for kernel version changes
#
#
PATCH_STR:=$(shell cat $(OCTEONTX_HOST_ROOT)/$(PATCHDIRS)/$(PATCH_FILE))
ifeq ($(findstring P_ACCESS_OK_PARAM_2,$(PATCH_STR)), P_ACCESS_OK_PARAM_2)
EXTRA_CFLAGS += -DP_ACCESS_OK_PARAM_2
endif
#
#

# The driver object file
obj-m         :=  octeon_drv.o
octeon_drv-y  :=  $(OBJS)


all: check_cnnic
	echo $(MAKEKERNEL)
	$(MAKEKERNEL)
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@rm -f $(BINDIR)/octeon_drv.ko; 
	@ln -s $(PWD)/octeon_drv.ko $(BINDIR) ; 
	@awk 'BEGIN {print "EXTRA_CFLAGS += \t\\"} {print "-D"$$2"=vf_"$$2"\t\\"}' Module.symvers  > redefine_symbols.mk


clean: check_cnnic
	@rm -rf $(BINDIR)/octeon_drv.ko *.ko .*.cmd *.mod.* *.o *~ .tmp_versions .*.o.d
	@rm -f modules.order Module.symvers *.ko.unsigned .cache.mk
	@rm -f ../../../osi/.*.cmd ../../../osi/*.o  ../../../osi/*~
	@rm -f ../test/.*.cmd ../test/*.o ../test/*~ *.ko 
	@rm -f redefine_symbols.mk
	@rm -f *.ur-safe ../../../osi/*.ur-safe

# $Id: Makefile 170599 2018-03-20 13:42:25Z vvelumuri $
