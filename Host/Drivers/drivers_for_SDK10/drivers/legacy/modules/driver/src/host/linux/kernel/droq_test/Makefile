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
# Makefile for PCI driver kernel application to demonstrate
# Octeon PCI output queue packet processing
#



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
EXTRA_CFLAGS += -I.    -I$(SUBDIRS)/../../../../common \
		-I$(SUBDIRS)/../../../../../inc -I$(SUBDIRS) -I$(SUBDIRS)/../drv/ \
		-D__SMP__ -O2 -Winline -Wall -Werror -finline-functions


EXTRA_CFLAGS += ${OCTDRVFLAGS}


KBUILD_EXTRA_SYMBOLS := $(SUBDIRS)/../drv/Module.symvers


#
# PCI Kernel application object files
#
OBJS = octeon_droq_test.o
OBJNAME = droq_test

default: check_cnnic check all 

check_cnnic:
ifndef CNNIC_ROOT
	@echo "####################################################"
	@echo "              CNNIC_ROOT not defined"     
	@echo " Run the nic-env-setup.sh script in the CNNIC root directory"
	@echo "####################################################"
	@exit 2
endif

ifeq ($(findstring OCTEON_VF,$(COMPILEFOR)), OCTEON_VF)
# For building VF kernel modules which runs on OCTEON VF BASE DRIVER (octeon_vf_drv.ko)
-include $(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/redefine_symbols.mk
KBUILD_EXTRA_SYMBOLS := $(CNNIC_ROOT)/modules/driver/src/host/linux/kernel/drv/octvf/Module.symvers
OBJNAME := vf_$(OBJNAME)

endif



# The driver object file
obj-m         :=  $(OBJNAME).o
$(OBJNAME)-y  :=  $(OBJS)

check:
	@if [ ! -e ../drv/octeon_drv.ko ]; \
	then \
		echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";\
		echo "              Warning: OCTEON Driver is not compiled."; \
		echo "Please compile the OCTEON Driver before compiling this application."; \
		echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";\
		exit 10; \
	fi

all: check_cnnic
	$(MAKE) -C $(kernel_source) SUBDIRS=`pwd` modules; 
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@rm -f $(BINDIR)/$(OBJNAME).ko; 
	@ln -s $(PWD)/$(OBJNAME).ko $(BINDIR) ; 

clean: check_cnnic
	@rm -rf $(BINDIR)/$(OBJNAME).ko *.ko .*.cmd *.mod.* *.o *~ .tmp_versions
	@rm -f modules.order Module.symvers *.ko.unsigned




# $Id: Makefile 140440 2016-06-11 13:55:46Z mchalla $ 
