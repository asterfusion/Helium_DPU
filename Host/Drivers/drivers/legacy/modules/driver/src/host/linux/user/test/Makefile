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
# Makefile for PCI driver user-space test program 
#


ifdef CNNIC_ROOT
include $(CNNIC_ROOT)/modules/driver/src/driver.mk
endif


#
# Compilation flags
#
INCLUDEFILES = 	-I../../kernel/driver/ -I../../../../../inc \
				-I../../../../common

CFLAGS = -Wall -Werror $(INCLUDEFILES) -O2 ${OCTDRVFLAGS} -D _GNU_SOURCE
LDFLAGS = -L$(BINDIR) -loctapi

ifeq ($(HOST_IS_OCTEON),1)
LDFLAGS += --static
endif



TARGET = oct_req 


all: check_cnnic $(TARGET)  links

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
	@ln -sf $(PWD)/oct_req $(BINDIR)/oct_req

%: Makefile %.c %.h ../api/liboctapi.a
	$(CC) $(CFLAGS) -g $(@F).c -o $@ $(LDFLAGS)

../api/liboctapi.a:
	cd ../api; $(MAKE) all;

clean: check_cnnic
	rm -f *.o *~ $(BINDIR)/$(TARGET) $(TARGET)


# $Id: Makefile 140440 2016-06-11 13:55:46Z mchalla $

