# Copyright (c) 2015 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Scripts require non-POSIX parts of bash
SHELL := $(shell which bash)

DL_CACHE_DIR = $(HOME)/Downloads
MAKE_ARGS ?= -j
BUILD_DIR        ?= $(CURDIR)/_build
INSTALL_DIR      ?= $(CURDIR)/_install
PKG_VERSION ?= $(shell git describe --abbrev=0 --match 'v[0-9]*' | cut -d- -f1 | cut -dv -f2 | cut -d. -f1,2)
PKG_SUFFIX ?= $(shell git log --oneline v$(PKG_VERSION)-rc0.. . | wc -l)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct .)
JOBS := $(if $(shell [ -f /proc/cpuinfo ] && head /proc/cpuinfo),\
	$(shell grep -c ^processor /proc/cpuinfo), 2)

B := $(BUILD_DIR)
I := $(INSTALL_DIR)

ifneq ($(shell which cmake3),)
CMAKE?=cmake3
else
CMAKE?=cmake
endif

ARCH_X86_64=$(filter x86_64,$(shell uname -m))
AARCH64=$(filter aarch64,$(shell uname -m))

INSTALL_QUICLY      ?= n
INSTALL_DPDK        ?= n
INSTALL_RDMA        ?= n
INSTALL_XDP         ?= n
INSTALL_OCTEON_ROC  ?= n
CONFIG_PACKAGE_LIST  =
INSTALL_PACKAGE_LIST =

ifeq ($(ARCH_X86_64), x86_64)
INSTALL_DPDK := y
endif

ifeq ($(AARCH64), aarch64)
INSTALL_OCTEON_ROC := y
endif

include packages.mk

ifeq (y, $(INSTALL_DPDK))
include packages/ipsec-mb.mk
include packages/dpdk.mk
INSTALL_RDMA        := y
CONFIG_PACKAGE_LIST += $(if $(ARCH_X86_64), ipsec-mb-config) dpdk-config
INSTALL_PACKAGE_LIST += $(if $(ARCH_X86_64), ipsec-mb-install) dpdk-install
endif

ifeq (y, $(INSTALL_QUICLY))
include packages/quicly.mk
INSTALL_PACKAGE_LIST += quicly-install
endif

ifeq (y, $(INSTALL_RDMA))
include packages/rdma-core.mk
CONFIG_PACKAGE_LIST += rdma-core-config
INSTALL_PACKAGE_LIST += rdma-core-install
endif

ifeq (y, $(INSTALL_XDP))
include packages/xdp-tools.mk
INSTALL_PACKAGE_LIST += xdp-tools-install
endif

ifeq (y, $(INSTALL_OCTEON_ROC))
include packages/octeon-roc.mk
INSTALL_PACKAGE_LIST += octeon-roc-install
endif

.PHONY: clean
clean:
	@rm -rf $(B) $(I)

.PHONY: install
install: $(INSTALL_PACKAGE_LIST)

.PHONY: config
config: $(CONFIG_PACKAGE_LIST)

##############################################################################
# .deb packaging
##############################################################################

DEB_VER := $(PKG_VERSION)
DEB_ARCH=$(shell dpkg --print-architecture 2> /dev/null)
DEV_DEB=vpp-ext-deps_$(DEB_VER)-$(PKG_SUFFIX)_$(DEB_ARCH).deb
INSTALLED_VER=$(shell dpkg-query --showformat='$${Version}' --show vpp-ext-deps 2> /dev/null)

.PHONY: build-deb install-deb check-deb

deb/debian/changelog: Makefile
	@echo "vpp-ext-deps ($(DEB_VER)-$(PKG_SUFFIX)) unstable; urgency=low" > $@
	@echo "" >> $@
	@echo "  * Version $(DEB_VER)" >> $@
	@echo "" >> $@
	@echo " -- VPP Dev <vpp-dev@lists.fd.io>  $(shell date -R --date=@${SOURCE_DATE_EPOCH})" >> $@

$(DEV_DEB): deb/debian/changelog
	@cd deb && dpkg-buildpackage -b -uc -us
	git clean -fdx deb

build-deb: $(DEV_DEB)

install-deb:
ifneq ($(INSTALLED_VER),$(DEB_VER)-$(PKG_SUFFIX))
	@make $(DEV_DEB)
	@sudo dpkg -i $(DEV_DEB)
else
	@echo "=========================================================="
	@echo " Up-to-date vpp-ext-deps package already installed"
	@echo "=========================================================="
endif

check-deb:
ifneq ($(INSTALLED_VER),$(DEB_VER)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Out of date vpp-ext-deps package installed."
	@echo " Installed: $(INSTALLED_VER)"
	@echo " Needed: $(DEB_VER)-$(PKG_SUFFIX)"
	@echo ""
	@echo " Please upgrade by invoking 'make install-ext-deps'"
	@echo " from the top level directory."
	@echo "=========================================================="
endif

##############################################################################
# .rpm packaging
##############################################################################

RPM_VER := $(PKG_VERSION)
RPM_ARCH=$(shell rpm --eval "%{_arch}" 2> /dev/null)
DEV_RPM=vpp-ext-deps-$(RPM_VER)-$(PKG_SUFFIX).$(RPM_ARCH).rpm
INSTALLED_RPM_VER=$(shell rpm -q --queryformat '%{VERSION}-%{RELEASE}' vpp-ext-deps 2> /dev/null | grep -v "vpp-ext-deps")

.PHONY: build-rpm install-rpm check-rpm

$(DEV_RPM): Makefile rpm/vpp-ext-deps.spec
	@rpmbuild -bb \
	  --define "_topdir $(CURDIR)/rpm" \
	  --define "_version $(RPM_VER)" \
	  --define "_release $(PKG_SUFFIX)" \
	  $(CURDIR)/rpm/vpp-ext-deps.spec
	mv rpm/RPMS/$(RPM_ARCH)/*.rpm .
	@git clean -fdx rpm

build-rpm: $(DEV_RPM)

install-rpm:
ifneq ($(INSTALLED_RPM_VER),$(RPM_VER)-$(PKG_SUFFIX))
	@$(MAKE) $(DEV_RPM)
	sudo rpm -e vpp-ext-deps || true
	sudo rpm -Uih --force $(DEV_RPM)
else
	@echo "=========================================================="
	@echo " Up-to-date vpp-ext-deps package already installed"
	@echo "=========================================================="
endif

check-rpm:
ifneq ($(INSTALLED_RPM_VER),$(RPM_VER)-$(PKG_SUFFIX))
	@echo "=========================================================="
	@echo " Out of date vpp-ext-deps package installed."
	@echo " Installed: $(INSTALLED_RPM_VER)"
	@echo " Needed: $(RPM_VER)-$(PKG_SUFFIX)"
	@echo ""
	@echo " Please upgrade by invoking 'make install-ext-deps'"
	@echo " from the top level directory."
	@echo "=========================================================="
endif

##############################################################################
# ebuild support
##############################################################################

.PHONY: ebuild-build ebuild-install

ebuild-build:
ifeq ($(INSTALLED_VER)$(INSTALLED_RPM_VER),)
	@echo "=========================================================="
	@echo "Building vpp-ext-deps from source. Consider installing"
	@echo "development package by invoking 'make install-ext-deps'"
	@echo "from the top level directory"
	@echo "=========================================================="
	$(MAKE) config
else
ifneq ($(INSTALLED_VER),)
	make check-deb
endif
ifneq ($(INSTALLED_RPM_VER),)
	$(MAKE) check-rpm
endif
endif

ebuild-install:
ifeq ($(INSTALLED_VER)$(INSTALLED_RPM_VER),)
	$(MAKE) install
endif
