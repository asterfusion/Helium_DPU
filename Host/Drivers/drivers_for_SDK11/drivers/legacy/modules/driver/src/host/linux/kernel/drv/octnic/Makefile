#Copyright (c) 2020 Marvell.
#SPDX-License-Identifier: GPL-2.0

# 
# Makefile for Linux Octeon NIC driver
#


#
# Compilation Flags.
# Select one or more attributes for the driver from the list below.
#
# COMPILEFOR = DEBUG OCTEON_VF
# 
# OCTEON_VF COMPILEFOR flag is introduced to BUILD and RUN VF drivers,
# kernel modules, userspace utilities/applications on the same host OS
# where PF base driver is running.
# For compiling the modules for VF, add OCTEON_VF to the COMPILEFOR flags
# in src/driver.mk file
#
# How it works:
# A. KERNEL MODULES
# 1. The PF BASE driver Makefile(src/host/linux/kernel/drv/Makefile) 
#    generates a redefine_symbols.mk file which should be included 
#    by the kernel modules to be compiled for VF.
# 2. The Makefile of kernel modules(octeon_vf, octnic, req_resp, 
#    droq_test, etc.) being compiled for VF will include	the 
#    redefine_symbols.mk generated in step 1 based on the
#    COMPILEFOR flag.
# B. USER SPACE UTILS/APPS
# 1. Based on the COMPILEFOR flag, the device handle file is selected
#    appropriately in "src/host/linux/user/api/octeon_user.c". If 
#    OCTEON_VF flag is present, then "/dev/octeon_vf_device" will be 
#    the device handle otherwise "/dev/octeon_device".
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

ifndef SUBDIRS
SUBDIRS=$(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/octnic
endif


#
# Setup compilation flags here
#
WARNINGS = -Wall -Werror -Wuninitialized -Wunused-function

#Disable warnings realted to __DATE__  and __TIME__, if the gcc version greather than 4.8
GCC_VER := $(shell echo `gcc -dumpversion | cut -f1-2 -d.` \>= 4.9 | bc )
ifeq ($(GCC_VER),1)
WARNINGS += -Wno-error=date-time -Wno-date-time
endif

INCLUDE += -I$(SUBDIRS)/..  -I$(SUBDIRS)/../../../../../common  \
	 -I$(SUBDIRS)/../../../../osi  -I$(SUBDIRS)/../../../../osi/octvf \
	 -I$(SUBDIRS)/../../../../../../inc -I$(SUBDIRS)

EXTRA_CFLAGS +=	-D__SMP__ -O2 -finline-functions $(INCLUDE) $(WARNINGS)

EXTRA_CFLAGS += ${OCTDRVFLAGS}


KBUILD_EXTRA_SYMBOLS := $(SUBDIRS)/../Module.symvers


#
# Driver object files
#

OBJS += octeon_netmain.o   \
        octeon_network.o   \
        octeon_vf_mbox.o   \
        ../../../../osi/octeon_nic.o

OBJNAME := octnic
OBJDBG  := octdbg

default: check_cnnic check all 

check_cnnic:
ifndef CNNIC_ROOT
	@echo "####################################################"
	@echo "              CNNIC_ROOT not defined"     
	@echo " Run the nic-env-setup.sh script in the CNNIC root directory"
	@echo "####################################################"
	@exit 2
endif

ifeq ($(findstring DEBUG,$(COMPILEFOR)), DEBUG)
# Creates debug levels.
# The default debug level is 0 when only critical messages are printed.
# Only errors are printed if this flag is not defined.
EXTRA_CFLAGS += -DCAVIUM_DEBUG=0
endif


ifeq ($(findstring OCTEON_VF,$(COMPILEFOR)), OCTEON_VF)
# For building VF kernel modules which runs on OCTEON VF BASE DRIVER (octeon_vf_drv.ko)
-include $(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/redefine_symbols.mk
KBUILD_EXTRA_SYMBOLS := $(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/octvf/Module.symvers
OBJNAME := oct_vf_nic

endif

# The driver object file
obj-m         :=  $(OBJNAME).o $(OBJDBG).o
$(OBJNAME)-y  :=  $(OBJS)
$(OBJDBG)-y   :=  octeon_debug.o


check:
	@if [ ! -e $(CNNIC_ROOT)/modules/driver/bin/octeon_drv.ko ]; \
	then \
		echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";\
                echo "              Warning: OCTEON Driver is not compiled."; \
                echo "Please compile the OCTEON Driver before compiling this NIC module."; \
                echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";\
                exit 10; \
	fi



all: check_cnnic
	$(MAKE) -C $(kernel_source) M=$(shell pwd)  modules;
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@rm -f $(BINDIR)/$(OBJNAME).ko $(BINDIR)/$(OBJDBG).ko; 
	@ln -s `pwd`/$(OBJNAME).ko $(BINDIR) ; 
	@ln -s `pwd`/$(OBJDBG).ko $(BINDIR) ; 


clean: check_cnnic
	rm -rf $(OBJS) $(BINDIR)/$(OBJNAME).ko $(BINDIR)/$(OBJDBG).ko *.ko .*.cmd *.mod.* *.o *~ .tmp_versions .cache.mk .*.o.d
	rm -f modules.order Module.symvers *.ko.unsigned *.ur-safe



# $Id: Makefile 140440 2016-06-11 13:55:46Z mchalla $ 
