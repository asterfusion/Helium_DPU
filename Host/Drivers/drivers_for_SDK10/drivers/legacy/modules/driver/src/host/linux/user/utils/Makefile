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
# Makefile for PCI driver host utilities 
#

ifdef CNNIC_ROOT
include $(CNNIC_ROOT)/modules/driver/src/driver.mk
endif

LIBOCTAPI = $(BINDIR)/liboctapi
OCT_DBG = oct_dbg
OCT_STATS = oct_stats

ifeq ($(findstring OCTEON_VF,$(COMPILEFOR)), OCTEON_VF)
#The binary name for the user space utils for vf is different from that of pf.
OCT_DBG = oct_vf_dbg
OCT_STATS = oct_vf_stats
endif


#
# The utilities to be compiled.
#
TARGETS = $(OCT_DBG) $(OCT_STATS) $(LIBOCTAPI)

all: check_cnnic $(TARGETS) links


check_cnnic:
ifndef CNNIC_ROOT
	@echo "####################################################"
	@echo "              CNNIC_ROOT not defined"     
	@echo " Run the nic-env-setup.sh script in the CNNIC root directory"
	@echo "####################################################"
	@exit 2
endif

#
# Compilation flags
#
CFLAGS = -Wall -Werror -I../../kernel/driver/ -I../../../../../inc -I../../../../common -O2 

ifeq ($(ENABLE_CURSES),1)
CFLAGS += -DUSE_CURSES -lcurses
endif

LDFLAGS = -L$(BINDIR) -loctapi

ifeq ($(HOST_IS_OCTEON),1)
LDFLAGS += --static
endif


links: check_cnnic
	@rm -f $(BINDIR) 2> /dev/null; mkdir -p $(BINDIR);
	@ln -sf $(PWD)/$(OCT_DBG) $(BINDIR);
	@ln -sf $(PWD)/$(OCT_STATS) $(BINDIR);

$(LIBOCTAPI):
	cd ../api; $(MAKE) -B;

$(OCT_STATS): oct_stats.c $(LIBOCTAPI)
	$(CC) $(CFLAGS) -g $< -o $@ $(LDFLAGS)

$(OCT_DBG): oct_dbg.c $(LIBOCTAPI)
	$(CC) $(CFLAGS) -g $< -o $@ $(LDFLAGS)

clean: check_cnnic
	rm -f *.o  *~ $(TARGETS);
	cd $(BINDIR); rm -f $(TARGETS);


# $Id: Makefile 140440 2016-06-11 13:55:46Z mchalla $
