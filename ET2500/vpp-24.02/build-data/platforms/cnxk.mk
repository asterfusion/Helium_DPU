# Copyright (c) 2023 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

ifeq ($(PLATFORM), cnxk)
cnxk_arch                    = aarch64
cnxk_native_tools            = vppapigen
cnxk_root_packages           = vpp

cnxk_debug_TAG_BUILD_TYPE    = debug
cnxk_TAG_BUILD_TYPE          = release
cnxk_clang_TAG_BUILD_TYPE    = release
cnxk_gcov_TAG_BUILD_TYPE     = gcov
cnxk_coverity_TAG_BUILD_TYPE = coverity
cnxk_target                  = aarch64-marvell-linux-gnu

_CURDIR                        := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

VPP_EXTRA_CMAKE_ARGS           +=-DCMAKE_TOOLCHAIN_FILE=$(_CURDIR)/../../src/cmake/cross.cmake
VPP_EXTRA_CMAKE_ARGS           +=-DCMAKE_C_FLAGS="${cnxk_c_flags}"

ifeq ($(OCTEON_VERSION), cn10k)
VPP_EXTRA_CMAKE_ARGS           +=-DVPP_PLATFORM=octeon10
elif ($(OCTEON_VERSION), cn9k)
VPP_EXTRA_CMAKE_ARGS           +=-DVPP_PLATFORM=octeon9
endif

ifeq ("$(CNXK_DISABLE_CCACHE)","1")
VPP_EXTRA_CMAKE_ARGS           += -DVPP_USE_CCACHE:BOOL=OFF
endif

ifndef CNXK_SDK_SYSROOT
 $(error CNXK_SDK_SYSROOT is not set)
endif

export cnxk_sysroot            = $(CNXK_SDK_SYSROOT)
export CROSS_TARGET            = $($(PLATFORM)_target)
export CROSS_ARCH              = $($(PLATFORM)_arch)
export CROSS_SDK_SYSROOT       = $($(PLATFORM)_sysroot)
endif
