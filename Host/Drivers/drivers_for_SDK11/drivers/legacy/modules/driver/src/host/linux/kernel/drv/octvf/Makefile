#Copyright (c) 2020 Marvell.
#SPDX-License-Identifier: GPL-2.0

#
# Makefile for Linux Octeon PCI driver
#


#
# Compilation Flags.
# Select one or more attributes for the driver from the list below. 
#
#  COMPILEFOR = DEBUG
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
SUBDIRS=$(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/octvf
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

INCLUDE += -I. -I$(SUBDIRS)/../../../../../common    -I$(SUBDIRS)/../../../../osi    \
	-I$(SUBDIRS)/../../../../osi/octvf \
	-I$(SUBDIRS)/../../../../../../inc  -I$(SUBDIRS)
INCLUDE += -I$(SUBDIRS)/../../test -I$(SUBDIRS)/../../drv
INCLUDE += -I$(SUBDIRS)/../octnic

EXTRA_CFLAGS +=	-D__SMP__ -O2 -finline-functions $(INCLUDE) $(WARNINGS)

#EXTRA_CFLAGS += -DFAST_PATH_DROQ_DISPATCH

EXTRA_CFLAGS += ${OCTDRVFLAGS}

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

ifeq ($(findstring OCTEON_VF,$(COMPILEFOR)), OCTEON_VF)
# For redefining exported symbol for vf driver(prefix "vf" to each symbol).
-include $(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/redefine_symbols.mk
endif

OBJS += octeon_vf_linux.o            	\
        octeon_vf_main.o             	\
	cavium_vf_proc.o             		\
	../octeon_poll.o           		\
	../octeon_ioctl.o            		\
	../device_access.o            		\
	../facility.o            		\
	../../../../osi/request_manager.o  \
	../../../../osi/octvf/octeon_vf_iq.o     \
	../../../../osi/response_manager.o \
	../../../../osi/pending_list.o     \
	../../../../osi/octvf/octeon_vf_device.o    \
	../../../../osi/octvf/cn83xx_vf_device.o    \
	../../../../osi/octvf/cn93xx_vf_device.o    \
	../../../../osi/octvf/cnxk_vf_device.o \
	../../../../osi/octeon_errata.o    \
	../../../../osi/octeon_mem_ops.o   \
	../../../../osi/request_manager.o   		\
	../../../../osi/octvf/octeon_vf_droq.o	\
	../../../../osi/octeon_mbox.o	\
	../../../../osi/octeon_model.o

OBJNAME := octeon_vf_drv

ifeq ($(findstring DEBUG,$(COMPILEFOR)), DEBUG)
# Creates debug levels.
# The default debug level is 0 when only critical messages are printed.
# Only errors are printed if this flag is not defined.
EXTRA_CFLAGS += -DCAVIUM_DEBUG=0
OBJS += ../../../../osi/octeon_debug.o
endif


# The driver object file
obj-m         :=  $(OBJNAME).o
$(OBJNAME)-y  :=  $(OBJS)


all: check_cnnic check
	$(MAKE) -C $(kernel_source) M=$(shell pwd)  modules;
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@rm -f $(BINDIR)/$(OBJNAME).ko; 
	@ln -s $(PWD)/$(OBJNAME).ko $(BINDIR) ; 


check:
	@if [ ! -e $(CNNIC_ROOT)/modules/driver/bin/octeon_drv.ko ]; \
	then \
		echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";\
		echo "              Warning: OCTEON Driver is not compiled."; \
		echo "Please compile the OCTEON Driver before compiling this"; \
		echo " 		OCTEON VF driver module."; \
		echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";\
		exit 10; \
	fi


clean: check_cnnic
	@rm -rf $(BINDIR)/$(OBJNAME).ko *.ko .*.cmd *.mod.* *.o *~ .tmp_versions .cache.mk .*.o.d
	@rm -f modules.order Module.symvers *.ko.unsigned
	@rm -f ../../drv/.*.cmd ../../drv/*.o  ../../*~
	@rm -f ../../../../osi/.*.cmd ../../../../osi/*.o  ../../../../osi/*~
	@rm -f ../../../../osi/octvf/.*.cmd ../../../../osi/octvf/*.o  ../../../../osi/octvf/*~
	@rm -f ../../test/.*.cmd ../../test/*.o ../../test/*~ *.ko 

# $Id: Makefile 118350 2015-05-26 10:15:21Z vattunuru $
