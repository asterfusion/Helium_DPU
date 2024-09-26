#  Copyright (C) 2020 Marvell International Ltd.
#
#  This program is provided "as is" without any warranty of any kind, and is
#  distributed under the applicable Marvell limited use license agreement.

OCTEONTX_HOST_ROOT = $(shell pwd)
export OCTEONTX_HOST_ROOT

SUBDIRS=drivers/legacy/modules/driver/src
SUBDIRS+=drivers/legacy/modules/driver/src/host/linux/kernel/drv/octnic
SUBDIRS+=drivers/mgmt_net
DIR=/usr/bin
TYPE=$(shell uname -m)

SUBDIRS+=drivers/octeon_drv_pre

PATCH_FILE=kernel.patch
export  PATCH_FILE
PATCHDIRS=patch_for_kernel
export  PATCHDIRS

ifeq ($(TYPE),x86_64)
	MRVL_DIR=/helium-mod-service/mrvl_x86
else
	MRVL_DIR=/helium-mod-service/mrvl_arm
endif

path_files:=$(shell ls $(PATCHDIRS)/*.sh)


all: patch $(SUBDIRS) 
	for d in $(SUBDIRS); do \
		if test -d $$d; then $(OCTEONTX_BUILD_ENV) $(MAKE) -s -C $$d || exit 1; fi; \
	done

clean:
	@echo > $(PATCHDIRS)/$(PATCH_FILE) 
	for d in $(SUBDIRS); do \
		if test -d $$d; then $(OCTEONTX_BUILD_ENV) $(MAKE) -s -C $$d $@ || exit 1; fi; \
	done

patch:
	@echo > $(PATCHDIRS)/$(PATCH_FILE) 	
	for d in $(path_files); do \
		. $$d || exit 1; \
	done \

	
install:
	echo -e "mgmt_net_path=$(OCTEONTX_HOST_ROOT)/drivers/mgmt_net/mgmt_net.ko\nocteon_drv_path=$(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/src/host/linux/kernel/drv/octeon_drv.ko\nvf_num=4\nocteon_drv_pre_path=$(OCTEONTX_HOST_ROOT)/drivers/octeon_drv_pre/octeon_drv_pre.ko\noctnic_path=$(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/bin/octnic.ko">/etc/helium_mod.conf
	chmod +x mod-service/helium-mod-service/*
	chmod +x mod-service/helium-mod-service/mrvl_arm/*
	chmod +x mod-service/helium-mod-service/mrvl_x86/*
	cp mod-service/helium-mod-service/*.sh ${DIR}
	cp mod-service/helium-mod-service/*.service /usr/lib/systemd/system/
	cp mod-service/$(MRVL_DIR)/mrvl* /${DIR}

	systemctl daemon-reload
	systemctl enable helium-mod.service



	
