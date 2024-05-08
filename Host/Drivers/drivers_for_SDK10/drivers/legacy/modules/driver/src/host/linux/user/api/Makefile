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
# Makefile for Octeon PCI user API library
#

ifdef CNNIC_ROOT
include $(CNNIC_ROOT)/modules/driver/src/driver.mk
endif

INCLUDEDIR = ../../../../../inc
COMMONDIR  = ../../../../common
CFLAGS =  -Wall -Werror -I../../kernel/driver -I$(INCLUDEDIR) -I$(COMMONDIR) -O2 -g -fPIC -DPIC 


ifeq ($(findstring OCTEON_VF,$(COMPILEFOR)), OCTEON_VF)
#For building user space utilities for VF. "/dev/octeon_vf_device" will be the device handle instead of /dev/octeon_device.
CFLAGS += -DCOMPILE_FOR_VF
endif

all: check_cnnic liboctapi.a links

check_cnnic:
ifndef CNNIC_ROOT
	@echo "####################################################"
	@echo "              CNNIC_ROOT not defined"     
	@echo " Run the nic-env-setup.sh script in the CNNIC root directory"
	@echo "####################################################"
	@exit 2
endif

links: check_cnnic
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@ln -fs $(PWD)/octeon_user.h $(INCLUDEDIR)/octeon_user.h
	@ln -sf $(PWD)/liboctapi.a $(BINDIR)

liboctapi.a: check_cnnic octeon_user.o
	$(AR) -r liboctapi.a octeon_user.o
	@ln -sf $(PWD)/liboctapi.a $(BINDIR)

octeon_user.o : octeon_user.c $(INCLUDEDIR)/cavium_defs.h
	@ln -fs $(PWD)/octeon_user.h $(INCLUDEDIR)/octeon_user.h
	$(CC) $(CFLAGS) -c octeon_user.c

clean: check_cnnic
	rm -f *.o *~  $(BINDIR)/liboctapi.a liboctapi.a $(INCLUDEDIR)/octeon_user.h

# $Id: Makefile 140440 2016-06-11 13:55:46Z mchalla $
