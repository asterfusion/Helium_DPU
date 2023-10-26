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
cnxk_uses_dpdk               = no

_CURDIR                          := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VPP_EXTRA_CMAKE_ARGS             +=-DCMAKE_TOOLCHAIN_FILE=$(_CURDIR)/../../src/cmake/cross.cmake

#Check for environment variables for throwing error
ifndef CNXK_SDK_SYSROOT
 $(error CNXK_SDK_SYSROOT is not set)
endif
ifndef OCTEONTX_SDK_KERNEL
 $(error OCTEONTX_SDK_KERNEL is not set)
endif

export cnxk_sysroot              = $(CNXK_SDK_SYSROOT)
export CROSS_TARGET              = $($(PLATFORM)_target)
export CROSS_ARCH                = $($(PLATFORM)_arch)
export CROSS_SDK_SYSROOT         = $($(PLATFORM)_sysroot)
endif
