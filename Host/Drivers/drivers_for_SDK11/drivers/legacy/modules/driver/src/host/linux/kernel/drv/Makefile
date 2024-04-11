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
SUBDIRS=$(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv
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


INCLUDE += -I. -I$(SUBDIRS)/../../../../common    -I$(SUBDIRS)/../../../osi    \
	-I$(SUBDIRS)/../../../osi/octvf	\
	-I$(SUBDIRS)/../../../../../inc  -I$(SUBDIRS)/../test -I$(SUBDIRS)
INCLUDE += -I$(SUBDIRS)/octnic

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
	../../../osi/cn93xx_pf_device.o    \
	../../../osi/cnxk_pf_device.o    \
	../../../osi/octeon_errata.o    \
	../../../osi/octeon_mem_ops.o   \
	../../../osi/octeon_droq.o	\
	../../../osi/octeon_mbox.o	\
	../../../osi/octeon_model.o

ifeq ($(findstring DEBUG,$(COMPILEFOR)), DEBUG)
# Creates debug levels.
# The default debug level is 0 when only critical messages are printed.
# Only errors are printed if this flag is not defined.
EXTRA_CFLAGS += -DCAVIUM_DEBUG=0
OBJS += ../../../osi/octeon_debug.o
endif

# The driver object file
obj-m         :=  octeon_drv.o
octeon_drv-y  :=  $(OBJS)


all: check_cnnic
	$(MAKE) -C $(kernel_source) M=$(shell pwd)  modules;
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@rm -f $(BINDIR)/octeon_drv.ko; 
	@ln -s $(PWD)/octeon_drv.ko $(BINDIR) ; 
	@awk 'BEGIN {print "EXTRA_CFLAGS += \t\\"} {print "-D"$$2"=vf_"$$2"\t\\"}' Module.symvers  > redefine_symbols.mk ;
	@awk '!/pport/' redefine_symbols.mk > tmp.mk && mv tmp.mk redefine_symbols.mk

clean: check_cnnic
	@rm -rf $(BINDIR)/octeon_drv.ko *.ko .*.cmd *.mod.* *.o *~ .tmp_versions .*.o.d
	@rm -f modules.order Module.symvers *.ko.unsigned .cache.mk
	@rm -f ../../../osi/.*.cmd ../../../osi/*.o  ../../../osi/*~
	@rm -f ../test/.*.cmd ../test/*.o ../test/*~ *.ko 
	@rm -f redefine_symbols.mk
	@rm -f *.ur-safe ../../../osi/*.ur-safe

# $Id: Makefile 170599 2018-03-20 13:42:25Z vvelumuri $
