#Copyright (c) 2020 Marvell.
#SPDX-License-Identifier: GPL-2.0

#
# This file provides system-wide defaults to compile the driver sources.
#
# IMPORTANT: Do not leave spaces at the end of directory paths.
#

#Get running kernel version
KERNEL_VERSION ?= $(shell uname -r)

# Enable this flag if the driver and applications will run on an OCTEON
# in PCI Host mode(ie, when OCTEON is the Host ).
#HOST_IS_OCTEON=1

# Define COMPILEFOR = OCTEON_VF to compile the kernel modules for VFs. These
# modules will run on OCTEON VF BASE drivers.
#COMPILEFOR = OCTEON_VF

ifeq ($(HOST_IS_OCTEON), 1)

CROSS_COMPILE := aarch64-marvell-linux-gnu-
export CROSS_COMPILE
ARCH = arm64
export ARCH

OCTDRVFLAGS  += -DOCTEON_HOST
# The compiler needs to be changed only for the host sources.
# No changes are made if the core application includes this file.
ifneq ($(findstring OCTEON_CORE_DRIVER,$(COMPILE)), OCTEON_CORE_DRIVER)
# Update the 'kernel_source' to match the location of the ARM Linux
# typically something like /path/to/xxx-pcie-ep-release-output/build/linux[-custom]
kernel_source := /path/to/arm/linux/sources/or/headers
CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
endif
else
kernel_source := /lib/modules/$(KERNEL_VERSION)/build
ENABLE_CURSES=1
endif

# The driver sources are assumed to be in this directory.
# Modify it if you installed the sources in a different directory.
#DRIVER_ROOT := $(OCTEON_ROOT)/components/driver

BINDIR := $(CNNIC_ROOT)/modules/driver/bin

#Enables Advanced Error Reporting of the PCIe bus
#OCTDRVFLAGS  += -DPCIE_AER

#extract kernel major version from kernel version
KERNEL_MAJOR = $(shell echo $(KERNEL_VERSION) | \
sed -e 's/^\([0-9][0-9]*\)\.[0-9][0-9]*\.[0-9][0-9]*.*/\1/')

#extract kernel minor version from kernel version
KERNEL_MINOR = $(shell echo $(KERNEL_VERSION) | \
sed -e 's/^[0-9][0-9]*\.\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')

#extarct kernel revision from kernel version
KERNEL_REVISION = $(shell echo $(KERNEL_VERSION) | \
sed -e 's/^[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/')

#subroutine for comparing kernel version
kernel_compare = $(shell \
echo test | awk '{ \
if($(KERNEL_MAJOR) > $(1)) {print 1} \
else if($(KERNEL_MAJOR) == $(1)){ \
if($(KERNEL_MINOR) > $(2)) {print 1} \
else if($(KERNEL_MINOR) == $(2)){ \
if($(KERNEL_REVISION) >= $(3)) {print 1} else { print 0 } \
}else {print 0}}else{print 0}}' \
)

#New flag for OCTEON-III models. Code specific to OCTEON-III will be kept under this.
#Disable the other models, if OCTEON-III is enabled.
#ifneq ($(or $(findstring OCTEON_CN73XX, $(OCTEON_MODEL)), \
            $(findstring OCTEON_CN78XX, $(OCTEON_MODEL)), \
            $(findstring OCTEON_CN23XX, $(OCTEON_MODEL))), )
OCTDRVFLAGS += -DENABLE_OCTEON_III=1

#Enable this flag to use driver loopback of packets
#Note: normal rx/tx will not work when this mode is enabled
#OCTDRVFLAGS += -DOCT_NIC_LOOPBACK
#OCTDRVFLAGS += -DOCT_TX2_ISM_INT

#Enable this flag for using host driver with only one PF
#OCTDRVFLAGS += -DUSE_SINGLE_PF

#Enable this flag for using host driver with emulator
#OCTDRVFLAGS += -DBUILD_FOR_EMULATOR
#endif

ifeq ($(PORT_EXTENDER_ENABLED),1)
ifeq ($(PPORT_INC_DIR),)
$(error PPORT_INC_DIR is not set)
endif
INCLUDE = -I$(PPORT_INC_DIR)
OCTDRVFLAGS += -DCONFIG_PPORT
endif

# $Id$ 
