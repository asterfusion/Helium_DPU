# Copyright (c) 2020 Marvell

armv8-crypto_version              := 0.1
armv8-crypto_tarball              := armv8-crypto-$(armv8-crypto_version).tar.gz
armv8-crypto_url                  := https://github.com/ARM-software/AArch64cryptolib.git
armv8-crypto_skip_tarball_checks  := 1
armv8-cryptotarball_strip_dirs    := 1
armv8-crypto_git_branch           ?= master
amrv8-crypto_git_commit           ?= master
#	git archive --format=tar --output=$@ --remote=$(armv8-crypto_url) $(armv8-crypto_git_commit)

define  armv8-crypto_download_cmds
       git clone $(armv8-crypto_url); \
       git -C AArch64cryptolib checkout 33c015d8f; \
       tar -C AArch64cryptolib -zcf $1 .; rm -rf AArch64cryptolib
endef

#define  armv8-crypto_update_cmds
#	git -C $(armv8-crypto_src_dir) pull
#endef

define  armv8-crypto_config_cmds
	export PKG_CONFIG_PATH=$(armv8-crypto_src_dir)/lib/pkgconfig/:$(PKG_CONFIG_PATH)	 \
	>>$(armv8-crypto_config_log) ;
endef

define  armv8-crypto_build_cmds
	make -C $(armv8-crypto_src_dir) -j$(JOBS)>$(armv8-crypto_build_log);
endef

define  armv8-crypto_install_cmds
	mkdir -p $(armv8-crypto_install_dir)/lib/pkgconfig
	cp -v $(armv8-crypto_src_dir)/pkgconfig/*.pc \
	  $(armv8-crypto_install_dir)/lib/pkgconfig >> $(armv8-crypto_install_log)
	cp -v $(armv8-crypto_src_dir)/libAArch64crypto.a \
	  $(armv8-crypto_install_dir)/lib >> $(armv8-crypto_install_log)
	if [ ! -z $(CROSS_TARGET) ];then cp -v $(armv8-crypto_src_dir)/libAArch64crypto.a \
	  $(CNXK_SDK_SYSROOT)/usr/lib >> $(armv8-crypto_install_log); fi
	if [ ! -z $(CROSS_TARGET) ];then cp -r $(armv8-crypto_src_dir)/*.h \
	  $(dpdk_src_dir)/; fi
endef

$(eval $(call package,armv8-crypto))

