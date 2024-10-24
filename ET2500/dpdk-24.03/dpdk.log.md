# Content

[Meson config](#Meson-config)

[Build DPDK](#Build-DPDK)

[Install DPDK](#Install-DPDK)

# Meson config

**meson build -Dmax_lcores=8**

```shell
root@OCTEONTX:~/Helium_DPU/ET2500/dpdk-24.03# meson build -Dmax_lcores=8
The Meson build system
Version: 1.0.1
Source dir: /root/Helium_DPU/ET2500/dpdk-24.03
Build dir: /root/Helium_DPU/ET2500/dpdk-24.03/build
Build type: native build
Program cat found: YES (/usr/bin/cat)
Project name: DPDK
Project version: 24.03.0
C compiler for the host machine: ccache cc (gcc 12.2.0 "cc (Debian 12.2.0-14) 12.2.0")
C linker for the host machine: cc ld.bfd 2.40
Host machine cpu family: aarch64
Host machine cpu: aarch64
Program pkg-config found: YES (/usr/bin/pkg-config)
Program check-symbols.sh found: YES (/root/Helium_DPU/ET2500/dpdk-24.03/buildtools/check-symbols.sh)
Program options-ibverbs-static.sh found: YES (/root/Helium_DPU/ET2500/dpdk-24.03/buildtools/options-ibverbs-static.sh)
Program python3 found: YES (/usr/bin/python3)
Program cat found: YES (/usr/bin/cat)
Compiler for C supports arguments -march=native: YES 
Checking for size of "void *" : 8
Checking for size of "void *" : 8
Compiler for C supports link arguments -Wl,--undefined-version: YES 
Library m found: YES
Library numa found: YES
Has header "numaif.h" : YES 
Library fdt found: NO
Library execinfo found: NO
Has header "execinfo.h" : YES 
Found pkg-config: /usr/bin/pkg-config (1.8.1)
Run-time dependency libarchive found: NO (tried pkgconfig)
Run-time dependency libbsd found: NO (tried pkgconfig)
Run-time dependency jansson found: NO (tried pkgconfig)
Run-time dependency openssl found: YES 3.0.14
Run-time dependency libpcap found: YES 1.10.3
Has header "pcap.h" with dependency libpcap: YES 
Compiler for C supports arguments -Wcast-qual: YES 
Compiler for C supports arguments -Wdeprecated: YES 
Compiler for C supports arguments -Wformat: YES 
Compiler for C supports arguments -Wformat-nonliteral: YES 
Compiler for C supports arguments -Wformat-security: YES 
Compiler for C supports arguments -Wmissing-declarations: YES 
Compiler for C supports arguments -Wmissing-prototypes: YES 
Compiler for C supports arguments -Wnested-externs: YES 
Compiler for C supports arguments -Wold-style-definition: YES 
Compiler for C supports arguments -Wpointer-arith: YES 
Compiler for C supports arguments -Wsign-compare: YES 
Compiler for C supports arguments -Wstrict-prototypes: YES 
Compiler for C supports arguments -Wundef: YES 
Compiler for C supports arguments -Wwrite-strings: YES 
Compiler for C supports arguments -Wno-address-of-packed-member: YES 
Compiler for C supports arguments -Wno-packed-not-aligned: YES 
Compiler for C supports arguments -Wno-missing-field-initializers: YES 
Compiler for C supports arguments -Wno-zero-length-bounds: YES 
Program /root/Helium_DPU/ET2500/dpdk-24.03/config/arm/armv8_machine.py found: YES (/root/Helium_DPU/ET2500/dpdk-24.03/config/arm/armv8_machine.py)
Message: Arm implementer: Arm
Message: Arm part number: 0xd49
Compiler for C supports arguments -mcpu=neoverse-n2: YES 
Compiler for C supports arguments -mcpu=neoverse-n2+sve2: YES 
Message: Using machine args: ['-mcpu=neoverse-n2+sve2']
Fetching value of define "__ARM_NEON" : 1 
Fetching value of define "__ARM_FEATURE_SVE" : 1 
Check usable header "arm_sve.h" : YES 
Fetching value of define "__ARM_FEATURE_CRC32" : 1 
Fetching value of define "__ARM_FEATURE_CRYPTO" :  
Compiler for C supports arguments -Wno-format-truncation: YES 
Checking for function "getentropy" : NO 
Fetching value of define "__ARM_FEATURE_CRYPTO" :  (cached)
Run-time dependency libelf found: YES 0.188
Compiler for C supports arguments -Wno-cast-qual: YES 
Fetching value of define "__ARM_NEON" : 1 (cached)
Fetching value of define "__ARM_NEON" : 1 (cached)
Fetching value of define "__ARM_FEATURE_BF16" :  
Has header "linux/userfaultfd.h" : YES 
Has header "linux/vduse.h" : YES 
Compiler for C supports arguments -Wno-format-truncation: YES (cached)
Compiler for C supports arguments -Wno-cast-qual: YES (cached)
Compiler for C supports arguments -Wno-pointer-arith: YES 
Compiler for C supports arguments -Wno-pointer-to-int-cast: YES 
Run-time dependency libmusdk found: NO (tried pkgconfig)
Compiler for C supports arguments -Wno-cast-qual: YES (cached)
Compiler for C supports arguments -Wno-pointer-arith: YES (cached)
Compiler for C supports arguments -std=c11: YES 
Compiler for C supports arguments -Wno-strict-prototypes: YES 
Compiler for C supports arguments -D_BSD_SOURCE: YES 
Compiler for C supports arguments -D_DEFAULT_SOURCE: YES 
Compiler for C supports arguments -D_XOPEN_SOURCE=600: YES 
Run-time dependency libmlx5 found: NO (tried pkgconfig)
Library mlx5 found: NO
Configuring mlx5_autoconf.h using configuration
Run-time dependency libcrypto found: YES 3.0.14
Compiler for C supports arguments -Wdisabled-optimization: YES 
Compiler for C supports arguments -Waggregate-return: YES 
Compiler for C supports arguments -Wbad-function-cast: YES 
Compiler for C supports arguments -Wno-sign-compare: YES 
Compiler for C supports arguments -Wno-unused-parameter: YES 
Compiler for C supports arguments -Wno-unused-variable: YES 
Compiler for C supports arguments -Wno-empty-body: YES 
Compiler for C supports arguments -Wno-unused-but-set-variable: YES 
Compiler for C supports arguments -Wno-uninitialized: YES 
Compiler for C supports arguments -Wno-pointer-arith: YES (cached)
Compiler for C supports arguments -Wno-pointer-arith: YES (cached)
Run-time dependency libxdp found: NO (tried pkgconfig)
Run-time dependency libbpf found: NO (tried pkgconfig)
Library bpf found: NO
Has header "linux/if_xdp.h" : YES 
Run-time dependency zlib found: YES 1.2.13
Compiler for C supports arguments -DSUPPORT_CFA_HW_ALL=1: YES 
Compiler for C supports arguments -flax-vector-conversions: YES 
Compiler for C supports arguments -Wno-strict-aliasing: YES 
Compiler for C supports arguments -Wno-pointer-arith: YES (cached)
Compiler for C supports arguments -Wno-uninitialized: YES (cached)
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Compiler for C supports arguments -Wno-unused-variable: YES (cached)
Compiler for C supports arguments -Wno-misleading-indentation: YES 
Compiler for C supports arguments -Wno-implicit-fallthrough: YES 
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Compiler for C supports arguments -Wno-unused-value: YES 
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -Wno-format-extra-args: YES 
Compiler for C supports arguments -Wno-unused-variable: YES (cached)
Compiler for C supports arguments -Wno-implicit-fallthrough: YES (cached)
Compiler for C supports arguments -Wno-sign-compare: YES (cached)
Compiler for C supports arguments -Wno-unused-value: YES (cached)
Compiler for C supports arguments -Wno-format: YES 
Compiler for C supports arguments -Wno-format-security: YES 
Compiler for C supports arguments -Wno-format-nonliteral: YES 
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -Wno-unused-but-set-variable: YES (cached)
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Compiler for C supports arguments -Wno-unused-value: YES (cached)
Compiler for C supports arguments -Wno-unused-but-set-variable: YES (cached)
Compiler for C supports arguments -Wno-unused-variable: YES (cached)
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Compiler for C supports arguments -Wno-array-bounds: YES 
Compiler for C supports arguments -Wno-unused-value: YES (cached)
Compiler for C supports arguments -Wno-unused-but-set-variable: YES (cached)
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Run-time dependency libmlx4 found: NO (tried pkgconfig)
Library mlx4 found: NO
Message: Disabling mlx5 [drivers/net/mlx5]: missing internal dependency "common_mlx5"
Run-time dependency libmusdk found: NO (tried pkgconfig)
Run-time dependency libmusdk found: NO (tried pkgconfig)
Run-time dependency netcope-common found: NO (tried pkgconfig)
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -flax-vector-conversions: YES (cached)
Compiler for C supports arguments -Wno-pointer-arith: YES (cached)
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Compiler for C supports arguments -Wno-sign-compare: YES (cached)
Compiler for C supports arguments -Wno-missing-prototypes: YES 
Compiler for C supports arguments -Wno-cast-qual: YES (cached)
Compiler for C supports arguments -Wno-unused-function: YES 
Compiler for C supports arguments -Wno-unused-variable: YES (cached)
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -Wno-missing-prototypes: YES (cached)
Compiler for C supports arguments -Wno-unused-value: YES (cached)
Compiler for C supports arguments -Wno-format-nonliteral: YES (cached)
Compiler for C supports arguments -Wno-shift-negative-value: YES 
Compiler for C supports arguments -Wno-unused-but-set-variable: YES (cached)
Compiler for C supports arguments -Wno-missing-declarations: YES 
Compiler for C supports arguments -Wno-maybe-uninitialized: YES 
Compiler for C supports arguments -Wno-strict-prototypes: YES (cached)
Compiler for C supports arguments -Wno-shift-negative-value: YES (cached)
Compiler for C supports arguments -Wno-implicit-fallthrough: YES (cached)
Compiler for C supports arguments -Wno-format-extra-args: YES (cached)
Compiler for C supports arguments -Wno-visibility: NO 
Compiler for C supports arguments -Wno-empty-body: YES (cached)
Compiler for C supports arguments -Wno-invalid-source-encoding: NO 
Compiler for C supports arguments -Wno-sometimes-uninitialized: NO 
Compiler for C supports arguments -Wno-pointer-bool-conversion: NO 
Compiler for C supports arguments -Wno-format-nonliteral: YES (cached)
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -Wdisabled-optimization: YES (cached)
Compiler for C supports arguments -Waggregate-return: YES (cached)
Compiler for C supports arguments -Wbad-function-cast: YES (cached)
Library atomic found: YES
Header "linux/pkt_cls.h" has symbol "TCA_FLOWER_UNSPEC" : YES 
Header "linux/pkt_cls.h" has symbol "TCA_FLOWER_KEY_VLAN_PRIO" : YES 
Header "linux/pkt_cls.h" has symbol "TCA_BPF_UNSPEC" : YES 
Header "linux/pkt_cls.h" has symbol "TCA_BPF_FD" : YES 
Header "linux/tc_act/tc_bpf.h" has symbol "TCA_ACT_BPF_UNSPEC" : YES 
Header "linux/tc_act/tc_bpf.h" has symbol "TCA_ACT_BPF_FD" : YES 
Configuring tap_autoconf.h using configuration
Compiler for C supports arguments -fno-prefetch-loop-arrays: YES 
Compiler for C supports arguments -Wno-maybe-uninitialized: YES (cached)
Compiler for C supports arguments -D_BSD_SOURCE: YES (cached)
Compiler for C supports arguments -D_DEFAULT_SOURCE: YES (cached)
Compiler for C supports arguments -D_XOPEN_SOURCE=600: YES (cached)
Compiler for C supports arguments -Wno-unused-parameter: YES (cached)
Compiler for C supports arguments -Wno-unused-value: YES (cached)
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -Wno-format-extra-args: YES (cached)
Run-time dependency libaarch64crypto found: NO (tried pkgconfig)
Dependency libcrypto found: YES 3.0.14 (cached)
Library IPSec_MB found: NO
Message: Disabling mlx5 [drivers/crypto/mlx5]: missing internal dependency "common_mlx5"
Run-time dependency libmusdk found: NO (tried pkgconfig)
Dependency libcrypto found: YES 3.0.14 (cached)
Run-time dependency libwd_crypto found: NO (tried pkgconfig)
Run-time dependency libwd found: NO (tried pkgconfig)
Run-time dependency libisal found: NO (tried pkgconfig)
Message: Disabling mlx5 [drivers/compress/mlx5]: missing internal dependency "common_mlx5"
Dependency zlib found: YES 1.2.13 (cached)
Message: Disabling mlx5 [drivers/regex/mlx5]: missing internal dependency "common_mlx5"
Message: drivers/ml/cnxk: libarchive not found
Message: drivers/ml/cnxk: jansson not found
Found CMake: /usr/bin/cmake (3.25.1)
Run-time dependency dlpack found: NO (tried cmake)
Message: drivers/ml/cnxk: dlpack not found
Run-time dependency dmlc found: NO (tried cmake)
Message: drivers/ml/cnxk: dmlc not found
Run-time dependency tvm found: NO (tried cmake)
Message: drivers/ml/cnxk: tvm_runtime not found
Run-time dependency tvmdp found: NO (tried pkgconfig)
Message: drivers/ml/cnxk: tvmdp not found
Message: drivers/ml/cnxk: Disabled TVM model support
Message: Disabling mlx5 [drivers/vdpa/mlx5]: missing internal dependency "common_mlx5"
Compiler for C supports arguments -flax-vector-conversions: YES (cached)
Compiler for C supports arguments -Wno-strict-aliasing: YES (cached)
Compiler for C supports arguments -Wno-format-nonliteral: YES (cached)
Run-time dependency flexran_sdk_ldpc_decoder_5gnr found: NO (tried pkgconfig and cmake)
Run-time dependency flexran_sdk_turbo found: NO (tried pkgconfig and cmake)
Run-time dependency flexran_sdk_ldpc_decoder_5gnr found: NO (tried pkgconfig and cmake)
Has header "cuda.h" : NO 
Has header "sys/epoll.h" : YES 
Dependency zlib found: YES 1.2.13 (cached)
Run-time dependency pcap found: YES 1.10.3
Compiler for C supports arguments -Wno-format-truncation: YES (cached)
Message: hugepage availability: true
Program test_telemetry.sh found: YES (/root/Helium_DPU/ET2500/dpdk-24.03/app/test/suites/test_telemetry.sh)
Program copy_data.py found: YES (/root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/copy_data.py)
WARNING: You should add the boolean check kwarg to the run_command call.
         It currently defaults to false,
         but it will default to true in future releases of meson.
         See also: https://github.com/mesonbuild/meson/issues/9300
Run-time dependency libtmc found: NO (tried pkgconfig)
Library tmc found: NO
Program doxygen found: NO
Program sphinx-build found: NO
Configuring rte_build_config.h using configuration

Message: 
=================

Applications Enabled
=================

apps:
        dumpcap, graph, pdump, proc-info, test-acl, test-bbdev, test-cmdline, test-compress-perf, 
        test-crypto-perf, test-dma-perf, test-eventdev, test-fib, test-flow-perf, test-gpudev, test-mldev, test-pipeline, 
        test-pmd, test-regex, test-sad, test-security-perf, test, 

Message: 
=================

Libraries Enabled
=================

libs:
        log, kvargs, argparse, telemetry, eal, ring, rcu, mempool, 
        mbuf, net, meter, ethdev, pci, cmdline, metrics, hash, 
        timer, acl, bbdev, bitratestats, bpf, cfgfile, compressdev, cryptodev, 
        distributor, dmadev, efd, eventdev, dispatcher, gpudev, gro, gso, 
        ip_frag, jobstats, latencystats, lpm, member, pcapng, power, rawdev, 
        regexdev, mldev, rib, reorder, sched, security, stack, vhost, 
        ipsec, pdcp, fib, port, pdump, table, pipeline, graph, 
        node, 

Message: 
===============

Drivers Enabled
===============

common:
        cpt, dpaax, iavf, idpf, ionic, octeontx, cnxk, nfp, 
        nitrox, qat, sfc_efx, 
bus:
        auxiliary, cdx, dpaa, fslmc, ifpga, pci, platform, uacce, 
        vdev, vmbus, 
mempool:
        bucket, cnxk, dpaa, dpaa2, octeontx, ring, stack, 
dma:
        cnxk, dpaa, dpaa2, hisilicon, odm, skeleton, 
net:
        af_packet, ark, atlantic, avp, axgbe, bnx2x, bnxt, bond, 
        cnxk, cpfl, cxgbe, dpaa, dpaa2, e1000, ena, enetc, 
        enetfec, enic, failsafe, fm10k, gve, hinic, hns3, i40e, 
        iavf, ice, idpf, igc, ionic, ixgbe, memif, netvsc, 
        nfp, ngbe, null, octeontx, octeon_ep, pcap, pfe, qede, 
        ring, sfc, softnic, tap, thunderx, txgbe, vdev_netvsc, vhost, 
        virtio, vmxnet3, 
raw:
        cnxk_bphy, cnxk_gpio, dpaa2_cmdif, ntb, skeleton, 
crypto:
        bcmfs, caam_jr, ccp, cnxk, dpaa_sec, dpaa2_sec, nitrox, null, 
        octeontx, openssl, scheduler, virtio, 
compress:
        nitrox, octeontx, zlib, 
regex:
        cn9k, 
ml:
        cnxk, 
vdpa:
        ifc, nfp, sfc, 
event:
        cnxk, dpaa, dpaa2, dsw, opdl, skeleton, sw, octeontx, 

baseband:
        acc, fpga_5gnr_fec, fpga_lte_fec, la12xx, null, turbo_sw, 
gpu:


Message: 
=================

Content Skipped
=================

apps:

libs:

drivers:
        common/mvep:    missing dependency, "libmusdk"
        common/mlx5:    missing dependency, "mlx5"
        dma/idxd:       only supported on x86
        dma/ioat:       only supported on x86
        net/af_xdp:     missing dependency, "libxdp >=1.2.2" and "libbpf"
        net/ipn3ke:     missing dependency, "libfdt"
        net/mana:       only supported on x86 Linux
        net/mlx4:       missing dependency, "mlx4"
        net/mlx5:       missing internal dependency, "common_mlx5"
        net/mvneta:     missing dependency, "libmusdk"
        net/mvpp2:      missing dependency, "libmusdk"
        net/nfb:        missing dependency, "libnfb"
        raw/ifpga:      missing dependency, "libfdt"
        crypto/armv8:   missing dependency, "libAArch64crypto"
        crypto/ipsec_mb:        missing dependency, "libIPSec_MB"
        crypto/mlx5:    missing internal dependency, "common_mlx5"
        crypto/mvsam:   missing dependency, "libmusdk"
        crypto/uadk:    missing dependency, "libwd"
        compress/isal:  missing dependency, "libisal"
        compress/mlx5:  missing internal dependency, "common_mlx5"
        regex/mlx5:     missing internal dependency, "common_mlx5"
        vdpa/mlx5:      missing internal dependency, "common_mlx5"
        event/dlb2:     only supported on x86_64 Linux
        gpu/cuda:       missing dependency, "cuda.h"


Build targets in project: 658
NOTICE: Future-deprecated features used:

 * 0.55.0: {'ExternalProgram.path'}

DPDK 24.03.0

  User defined options
    max_lcores: 8

Found ninja-1.11.1 at /usr/bin/ninja
WARNING: Running the setup command as `meson [options]` instead of `meson setup [options]` is ambiguous and deprecated.
```

# Build DPDK

```shell
root@OCTEONTX:~/Helium_DPU/ET2500/dpdk-24.03# ninja -C build
ninja: Entering directory `build'
[2980/2980] Linking target marvell-ci/test/cnxk-tests/cpt_raw_test/cpt_raw_test
```

# Install DPDK

```shell
root@OCTEONTX:~/Helium_DPU/ET2500/dpdk-24.03# ninja -C build install 
ninja: Entering directory `build'
[0/1] Installing files.
Installing subdir /root/Helium_DPU/ET2500/dpdk-24.03/examples to /usr/local/share/dpdk/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bbdev_app/Makefile to /usr/local/share/dpdk/examples/bbdev_app
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bbdev_app/main.c to /usr/local/share/dpdk/examples/bbdev_app
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/dma/dmafwd.c to /usr/local/share/dpdk/examples/dma
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/dma/Makefile to /usr/local/share/dpdk/examples/dma
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-jobstats/Makefile to /usr/local/share/dpdk/examples/l2fwd-jobstats
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-jobstats/main.c to /usr/local/share/dpdk/examples/l2fwd-jobstats
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/eventdev_pipeline/pipeline_worker_tx.c to /usr/local/share/dpdk/examples/eventdev_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/eventdev_pipeline/Makefile to /usr/local/share/dpdk/examples/eventdev_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/eventdev_pipeline/main.c to /usr/local/share/dpdk/examples/eventdev_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/eventdev_pipeline/pipeline_worker_generic.c to /usr/local/share/dpdk/examples/eventdev_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/eventdev_pipeline/pipeline_common.h to /usr/local/share/dpdk/examples/eventdev_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_fragmentation/Makefile to /usr/local/share/dpdk/examples/ip_fragmentation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_fragmentation/main.c to /usr/local/share/dpdk/examples/ip_fragmentation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_blk/Makefile to /usr/local/share/dpdk/examples/vhost_blk
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_blk/blk_spec.h to /usr/local/share/dpdk/examples/vhost_blk
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_blk/vhost_blk.c to /usr/local/share/dpdk/examples/vhost_blk
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_blk/vhost_blk.h to /usr/local/share/dpdk/examples/vhost_blk
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_blk/vhost_blk_compat.c to /usr/local/share/dpdk/examples/vhost_blk
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_blk/blk.c to /usr/local/share/dpdk/examples/vhost_blk
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/helloworld/Makefile to /usr/local/share/dpdk/examples/helloworld
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/helloworld/main.c to /usr/local/share/dpdk/examples/helloworld
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vdpa/Makefile to /usr/local/share/dpdk/examples/vdpa
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vdpa/commands.list to /usr/local/share/dpdk/examples/vdpa
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vdpa/main.c to /usr/local/share/dpdk/examples/vdpa
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vdpa/vdpa_blk_compact.h to /usr/local/share/dpdk/examples/vdpa
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/common/pkt_group.h to /usr/local/share/dpdk/examples/common
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/common/sse/port_group.h to /usr/local/share/dpdk/examples/common/sse
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/common/neon/port_group.h to /usr/local/share/dpdk/examples/common/neon
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/common/altivec/port_group.h to /usr/local/share/dpdk/examples/common/altivec
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/cmdline/Makefile to /usr/local/share/dpdk/examples/cmdline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/cmdline/main.c to /usr/local/share/dpdk/examples/cmdline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/cmdline/parse_obj_list.h to /usr/local/share/dpdk/examples/cmdline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/cmdline/parse_obj_list.c to /usr/local/share/dpdk/examples/cmdline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/cmdline/commands.h to /usr/local/share/dpdk/examples/cmdline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/cmdline/commands.c to /usr/local/share/dpdk/examples/cmdline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/Makefile to /usr/local/share/dpdk/examples/ethtool
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/lib/rte_ethtool.c to /usr/local/share/dpdk/examples/ethtool/lib
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/lib/Makefile to /usr/local/share/dpdk/examples/ethtool/lib
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/lib/rte_ethtool.h to /usr/local/share/dpdk/examples/ethtool/lib
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/ethtool-app/ethapp.c to /usr/local/share/dpdk/examples/ethtool/ethtool-app
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/ethtool-app/ethapp.h to /usr/local/share/dpdk/examples/ethtool/ethtool-app
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/ethtool-app/Makefile to /usr/local/share/dpdk/examples/ethtool/ethtool-app
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ethtool/ethtool-app/main.c to /usr/local/share/dpdk/examples/ethtool/ethtool-app
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ntb/Makefile to /usr/local/share/dpdk/examples/ntb
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ntb/commands.list to /usr/local/share/dpdk/examples/ntb
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ntb/ntb_fwd.c to /usr/local/share/dpdk/examples/ntb
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_rsa.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/Makefile to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_dev_self_test.h to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_gcm.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/main.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_tdes.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_sha.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation.h to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_dev_self_test.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_aes.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_hmac.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_ccm.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_ecdsa.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_xts.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/fips_validation/fips_validation_cmac.c to /usr/local/share/dpdk/examples/fips_validation
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-cat/Makefile to /usr/local/share/dpdk/examples/l2fwd-cat
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-cat/cat.h to /usr/local/share/dpdk/examples/l2fwd-cat
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-cat/cat.c to /usr/local/share/dpdk/examples/l2fwd-cat
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-cat/l2fwd-cat.c to /usr/local/share/dpdk/examples/l2fwd-cat
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/link.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/Makefile to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/conn.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/cli.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/swq.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/link.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/mempool.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/main.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/thread.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/parser.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/mempool.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/tap.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/pipeline.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/cryptodev.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/common.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/tmgr.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/tmgr.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/pipeline.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/swq.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/conn.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/thread.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/cryptodev.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/cli.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/parser.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/action.c to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/tap.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/action.h to /usr/local/share/dpdk/examples/ip_pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/l2fwd.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/tap.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/route.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/flow.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/firewall.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/flow_crypto.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/route_ecmp.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_pipeline/examples/rss.cli to /usr/local/share/dpdk/examples/ip_pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd/Makefile to /usr/local/share/dpdk/examples/l2fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd/main.c to /usr/local/share/dpdk/examples/l2fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/rxtx_callbacks/Makefile to /usr/local/share/dpdk/examples/rxtx_callbacks
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/rxtx_callbacks/main.c to /usr/local/share/dpdk/examples/rxtx_callbacks
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-crypto/Makefile to /usr/local/share/dpdk/examples/l2fwd-crypto
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-crypto/main.c to /usr/local/share/dpdk/examples/l2fwd-crypto
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-keepalive/Makefile to /usr/local/share/dpdk/examples/l2fwd-keepalive
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-keepalive/main.c to /usr/local/share/dpdk/examples/l2fwd-keepalive
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-keepalive/shm.h to /usr/local/share/dpdk/examples/l2fwd-keepalive
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-keepalive/shm.c to /usr/local/share/dpdk/examples/l2fwd-keepalive
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-keepalive/ka-agent/Makefile to /usr/local/share/dpdk/examples/l2fwd-keepalive/ka-agent
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-keepalive/ka-agent/main.c to /usr/local/share/dpdk/examples/l2fwd-keepalive/ka-agent
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/packet_ordering/Makefile to /usr/local/share/dpdk/examples/packet_ordering
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/packet_ordering/main.c to /usr/local/share/dpdk/examples/packet_ordering
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/sad.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/rt.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec_process.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/Makefile to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/esp.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec_lpm_neon.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec_worker.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/sp6.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/event_helper.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/flow.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/parser.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec_neon.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec-secgw.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/flow.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/sp4.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/esp.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/event_helper.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ep1.cfg to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec-secgw.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/sad.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/sa.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipsec_worker.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/parser.c to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ipip.h to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/ep0.cfg to /usr/local/share/dpdk/examples/ipsec-secgw
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_3descbc_sha1_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_null_header_reconstruct.py to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_aescbc_sha1_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_aesctr_sha1_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_aesgcm_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/linux_test.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_aesgcm_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/data_rxtx.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/pkttest.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_aesgcm_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_aesctr_sha1_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_3descbc_sha1_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/pkttest.py to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_3descbc_sha1_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/bypass_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_aesctr_sha1_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_aesgcm_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_aescbc_sha1_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_aesctr_sha1_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_ipv6opts.py to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/common_defs_secgw.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/tun_3descbc_sha1_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_aescbc_sha1_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/load_env.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/run_test.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipsec-secgw/test/trs_aescbc_sha1_common_defs.sh to /usr/local/share/dpdk/examples/ipsec-secgw/test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/channel_monitor.h to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/channel_manager.h to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/Makefile to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/oob_monitor_x86.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/main.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/parse.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/parse.h to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/vm_power_cli.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/oob_monitor.h to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/vm_power_cli.h to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/power_manager.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/channel_manager.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/power_manager.h to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/channel_monitor.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/oob_monitor_nop.c to /usr/local/share/dpdk/examples/vm_power_manager
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/guest_cli/Makefile to /usr/local/share/dpdk/examples/vm_power_manager/guest_cli
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/guest_cli/vm_power_cli_guest.h to /usr/local/share/dpdk/examples/vm_power_manager/guest_cli
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/guest_cli/main.c to /usr/local/share/dpdk/examples/vm_power_manager/guest_cli
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/guest_cli/parse.c to /usr/local/share/dpdk/examples/vm_power_manager/guest_cli
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/guest_cli/parse.h to /usr/local/share/dpdk/examples/vm_power_manager/guest_cli
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vm_power_manager/guest_cli/vm_power_cli_guest.c to /usr/local/share/dpdk/examples/vm_power_manager/guest_cli
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_meter/Makefile to /usr/local/share/dpdk/examples/qos_meter
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_meter/main.h to /usr/local/share/dpdk/examples/qos_meter
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_meter/rte_policer.c to /usr/local/share/dpdk/examples/qos_meter
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_meter/main.c to /usr/local/share/dpdk/examples/qos_meter
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_meter/rte_policer.h to /usr/local/share/dpdk/examples/qos_meter
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-power/perf_core.h to /usr/local/share/dpdk/examples/l3fwd-power
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-power/Makefile to /usr/local/share/dpdk/examples/l3fwd-power
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-power/main.h to /usr/local/share/dpdk/examples/l3fwd-power
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-power/main.c to /usr/local/share/dpdk/examples/l3fwd-power
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-power/perf_core.c to /usr/local/share/dpdk/examples/l3fwd-power
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bond/Makefile to /usr/local/share/dpdk/examples/bond
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bond/commands.list to /usr/local/share/dpdk/examples/bond
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bond/main.c to /usr/local/share/dpdk/examples/bond
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipv4_multicast/Makefile to /usr/local/share/dpdk/examples/ipv4_multicast
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ipv4_multicast/main.c to /usr/local/share/dpdk/examples/ipv4_multicast
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vmdq_dcb/Makefile to /usr/local/share/dpdk/examples/vmdq_dcb
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vmdq_dcb/main.c to /usr/local/share/dpdk/examples/vmdq_dcb
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/flow_filtering/Makefile to /usr/local/share/dpdk/examples/flow_filtering
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/flow_filtering/main.c to /usr/local/share/dpdk/examples/flow_filtering
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/flow_filtering/flow_blocks.c to /usr/local/share/dpdk/examples/flow_filtering
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/link_status_interrupt/Makefile to /usr/local/share/dpdk/examples/link_status_interrupt
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/link_status_interrupt/main.c to /usr/local/share/dpdk/examples/link_status_interrupt
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_crypto/Makefile to /usr/local/share/dpdk/examples/vhost_crypto
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost_crypto/main.c to /usr/local/share/dpdk/examples/vhost_crypto
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/service_cores/Makefile to /usr/local/share/dpdk/examples/service_cores
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/service_cores/main.c to /usr/local/share/dpdk/examples/service_cores
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/distributor/Makefile to /usr/local/share/dpdk/examples/distributor
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/distributor/main.c to /usr/local/share/dpdk/examples/distributor
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-graph/Makefile to /usr/local/share/dpdk/examples/l3fwd-graph
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd-graph/main.c to /usr/local/share/dpdk/examples/l3fwd-graph
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/skeleton/Makefile to /usr/local/share/dpdk/examples/skeleton
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/skeleton/basicfwd.c to /usr/local/share/dpdk/examples/skeleton
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-macsec/Makefile to /usr/local/share/dpdk/examples/l2fwd-macsec
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-macsec/main.c to /usr/local/share/dpdk/examples/l2fwd-macsec
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_common.h to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_event_generic.c to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/Makefile to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/main.c to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_event_internal_port.c to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_poll.h to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_event.c to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_event.h to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_poll.c to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l2fwd-event/l2fwd_common.c to /usr/local/share/dpdk/examples/l2fwd-event
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ptpclient/Makefile to /usr/local/share/dpdk/examples/ptpclient
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ptpclient/ptpclient.c to /usr/local/share/dpdk/examples/ptpclient
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/Makefile to /usr/local/share/dpdk/examples/multi_process
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/simple_mp/Makefile to /usr/local/share/dpdk/examples/multi_process/simple_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/simple_mp/commands.list to /usr/local/share/dpdk/examples/multi_process/simple_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/simple_mp/main.c to /usr/local/share/dpdk/examples/multi_process/simple_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/simple_mp/mp_commands.h to /usr/local/share/dpdk/examples/multi_process/simple_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/simple_mp/mp_commands.c to /usr/local/share/dpdk/examples/multi_process/simple_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/symmetric_mp/Makefile to /usr/local/share/dpdk/examples/multi_process/symmetric_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/symmetric_mp/main.c to /usr/local/share/dpdk/examples/multi_process/symmetric_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/hotplug_mp/Makefile to /usr/local/share/dpdk/examples/multi_process/hotplug_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/hotplug_mp/commands.list to /usr/local/share/dpdk/examples/multi_process/hotplug_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/hotplug_mp/main.c to /usr/local/share/dpdk/examples/multi_process/hotplug_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/hotplug_mp/commands.c to /usr/local/share/dpdk/examples/multi_process/hotplug_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/Makefile to /usr/local/share/dpdk/examples/multi_process/client_server_mp
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/shared/common.h to /usr/local/share/dpdk/examples/multi_process/client_server_mp/shared
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_server/init.h to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_server/Makefile to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_server/args.c to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_server/main.c to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_server/init.c to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_server/args.h to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_client/client.c to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_client
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/multi_process/client_server_mp/mp_client/Makefile to /usr/local/share/dpdk/examples/multi_process/client_server_mp/mp_client
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bpf/README to /usr/local/share/dpdk/examples/bpf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bpf/t1.c to /usr/local/share/dpdk/examples/bpf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bpf/t3.c to /usr/local/share/dpdk/examples/bpf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bpf/dummy.c to /usr/local/share/dpdk/examples/bpf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/bpf/t2.c to /usr/local/share/dpdk/examples/bpf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/obj.h to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/Makefile to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/conn.h to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/cli.c to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/main.c to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/thread.h to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/conn.c to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/thread.c to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/cli.h to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/obj.c to /usr/local/share/dpdk/examples/pipeline
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ipv6_addr_swap.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/fib_routing_table.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/recirculation.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/l2fwd.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/mirroring.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/vxlan_pcap.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/vxlan_table.py to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/vxlan_table.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/varbit.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/mirroring.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/meter.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/l2fwd_macswp_pcap.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/selector.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/vxlan.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/fib_nexthop_table.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/registers.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/fib_nexthop_group_table.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/l2fwd_macswp.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/selector.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/packet.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ipsec.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/fib.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/hash_func.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ipsec.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ipsec_sa.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/hash_func.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/learner.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/learner.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/vxlan.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ipsec.io to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/pcap.io to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ethdev.io to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/rss.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/ipv6_addr_swap.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/recirculation.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/fib.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/rss.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/selector.txt to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/meter.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/l2fwd.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/varbit.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/l2fwd_pcap.cli to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/registers.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/pipeline/examples/l2fwd_macswp.spec to /usr/local/share/dpdk/examples/pipeline/examples
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/em_default_v4.cfg to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_event_generic.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_acl_scalar.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/Makefile to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_em_hlm_sse.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_em_hlm_neon.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_fib.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_event.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_event.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/main.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_event_internal_port.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_em.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/lpm_default_v4.cfg to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_acl.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/lpm_route_parse.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/em_route_parse.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_common.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/em_default_v6.cfg to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_acl.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_lpm_neon.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_lpm.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_sse.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_lpm_sse.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_lpm_altivec.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_lpm.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_route.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_em_hlm.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_altivec.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/lpm_default_v6.cfg to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_neon.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_em_sequential.h to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/l3fwd/l3fwd_em.c to /usr/local/share/dpdk/examples/l3fwd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_reassembly/Makefile to /usr/local/share/dpdk/examples/ip_reassembly
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/ip_reassembly/main.c to /usr/local/share/dpdk/examples/ip_reassembly
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost/Makefile to /usr/local/share/dpdk/examples/vhost
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost/virtio_net.c to /usr/local/share/dpdk/examples/vhost
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost/main.h to /usr/local/share/dpdk/examples/vhost
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vhost/main.c to /usr/local/share/dpdk/examples/vhost
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/timer/Makefile to /usr/local/share/dpdk/examples/timer
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/timer/main.c to /usr/local/share/dpdk/examples/timer
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/profile_pie.cfg to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/profile_ov.cfg to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/Makefile to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/args.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/main.h to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/main.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/profile_red.cfg to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/cfg_file.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/init.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/cmdline.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/profile.cfg to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/app_thread.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/cfg_file.h to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/qos_sched/stats.c to /usr/local/share/dpdk/examples/qos_sched
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vmdq/Makefile to /usr/local/share/dpdk/examples/vmdq
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/vmdq/main.c to /usr/local/share/dpdk/examples/vmdq
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/Makefile to /usr/local/share/dpdk/examples/server_node_efd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/shared/common.h to /usr/local/share/dpdk/examples/server_node_efd/shared
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_node/Makefile to /usr/local/share/dpdk/examples/server_node_efd/efd_node
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_node/node.c to /usr/local/share/dpdk/examples/server_node_efd/efd_node
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_server/init.h to /usr/local/share/dpdk/examples/server_node_efd/efd_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_server/Makefile to /usr/local/share/dpdk/examples/server_node_efd/efd_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_server/args.c to /usr/local/share/dpdk/examples/server_node_efd/efd_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_server/main.c to /usr/local/share/dpdk/examples/server_node_efd/efd_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_server/init.c to /usr/local/share/dpdk/examples/server_node_efd/efd_server
Installing /root/Helium_DPU/ET2500/dpdk-24.03/examples/server_node_efd/efd_server/args.h to /usr/local/share/dpdk/examples/server_node_efd/efd_server
Installing lib/librte_log.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_log.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_kvargs.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_kvargs.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_argparse.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_argparse.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_telemetry.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_telemetry.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_eal.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_eal.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ring.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ring.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_rcu.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_rcu.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_mempool.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_mempool.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_mbuf.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_mbuf.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_net.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_net.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_meter.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_meter.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ethdev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ethdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pci.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pci.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_cmdline.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_cmdline.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_metrics.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_metrics.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_hash.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_hash.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_timer.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_timer.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_acl.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_acl.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_bbdev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_bbdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_bitratestats.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_bitratestats.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_bpf.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_bpf.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_cfgfile.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_cfgfile.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_compressdev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_compressdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_cryptodev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_cryptodev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_distributor.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_distributor.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_dmadev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_dmadev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_efd.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_efd.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_eventdev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_eventdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_dispatcher.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_dispatcher.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_gpudev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_gpudev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_gro.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_gro.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_gso.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_gso.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ip_frag.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ip_frag.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_jobstats.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_jobstats.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_latencystats.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_latencystats.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_lpm.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_lpm.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_member.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_member.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pcapng.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pcapng.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_power.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_power.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_rawdev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_rawdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_regexdev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_regexdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_mldev.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_mldev.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_rib.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_rib.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_reorder.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_reorder.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_sched.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_sched.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_security.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_security.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_stack.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_stack.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_vhost.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_vhost.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ipsec.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_ipsec.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pdcp.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pdcp.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_fib.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_fib.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_port.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_port.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pdump.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pdump.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_table.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_table.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pipeline.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_pipeline.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_graph.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_graph.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_node.a to /usr/local/lib/aarch64-linux-gnu
Installing lib/librte_node.so.24.1 to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_cpt.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_cpt.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_dpaax.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_dpaax.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_iavf.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_iavf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_idpf.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_idpf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_ionic.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_ionic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_octeontx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_auxiliary.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_auxiliary.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_cdx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_cdx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_dpaa.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_fslmc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_fslmc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_ifpga.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_ifpga.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_pci.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_pci.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_platform.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_platform.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_uacce.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_uacce.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_vdev.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_vdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_bus_vmbus.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_bus_vmbus.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_nfp.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_nfp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_nitrox.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_nitrox.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_qat.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_qat.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_common_sfc_efx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_common_sfc_efx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_bucket.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_bucket.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_dpaa.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_dpaa2.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_octeontx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_ring.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_ring.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_mempool_stack.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_mempool_stack.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_dma_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_dma_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_dma_dpaa.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_dma_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_dma_dpaa2.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_dma_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_dma_hisilicon.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_dma_hisilicon.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_dma_odm.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_dma_odm.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_dma_skeleton.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_dma_skeleton.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_af_packet.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_af_packet.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ark.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ark.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_atlantic.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_atlantic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_avp.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_avp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_axgbe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_axgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_bnx2x.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_bnx2x.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_bnxt.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_bnxt.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_bond.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_bond.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_cpfl.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_cpfl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_cxgbe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_cxgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_dpaa.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_dpaa2.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_e1000.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_e1000.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ena.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ena.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_enetc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_enetc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_enetfec.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_enetfec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_enic.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_enic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_failsafe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_failsafe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_fm10k.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_fm10k.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_gve.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_gve.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_hinic.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_hinic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_hns3.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_hns3.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_i40e.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_i40e.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_iavf.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_iavf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ice.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ice.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_idpf.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_idpf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_igc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_igc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ionic.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ionic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ixgbe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ixgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_memif.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_memif.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_netvsc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_netvsc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_nfp.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_nfp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ngbe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ngbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_null.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_null.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_octeontx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_octeon_ep.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_octeon_ep.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_pcap.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_pcap.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_pfe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_pfe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_qede.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_qede.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_ring.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_ring.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_sfc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_sfc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_softnic.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_softnic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_tap.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_tap.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_thunderx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_thunderx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_txgbe.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_txgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_vdev_netvsc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_vdev_netvsc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_vhost.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_vhost.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_virtio.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_virtio.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_net_vmxnet3.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_net_vmxnet3.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_raw_cnxk_bphy.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_raw_cnxk_bphy.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_raw_cnxk_gpio.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_raw_cnxk_gpio.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_raw_dpaa2_cmdif.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_raw_dpaa2_cmdif.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_raw_ntb.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_raw_ntb.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_raw_skeleton.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_raw_skeleton.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_bcmfs.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_bcmfs.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_caam_jr.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_caam_jr.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_ccp.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_ccp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_dpaa_sec.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_dpaa_sec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_dpaa2_sec.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_dpaa2_sec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_nitrox.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_nitrox.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_null.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_null.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_octeontx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_openssl.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_openssl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_scheduler.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_scheduler.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_crypto_virtio.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_crypto_virtio.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_compress_nitrox.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_compress_nitrox.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_compress_octeontx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_compress_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_compress_zlib.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_compress_zlib.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_regex_cn9k.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_regex_cn9k.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_ml_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_ml_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_vdpa_ifc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_vdpa_ifc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_vdpa_nfp.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_vdpa_nfp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_vdpa_sfc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_vdpa_sfc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_cnxk.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_dpaa.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_dpaa2.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_dsw.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_dsw.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_opdl.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_opdl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_skeleton.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_skeleton.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_sw.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_sw.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_event_octeontx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_event_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_baseband_acc.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_baseband_acc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_baseband_fpga_5gnr_fec.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_baseband_fpga_5gnr_fec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_baseband_fpga_lte_fec.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_baseband_fpga_lte_fec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_baseband_la12xx.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_baseband_la12xx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_baseband_null.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_baseband_null.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing drivers/librte_baseband_turbo_sw.a to /usr/local/lib/aarch64-linux-gnu
Installing drivers/librte_baseband_turbo_sw.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1
Installing app/dpdk-dumpcap to /usr/local/bin
Installing app/dpdk-graph to /usr/local/bin
Installing app/dpdk-pdump to /usr/local/bin
Installing app/dpdk-proc-info to /usr/local/bin
Installing app/dpdk-test-acl to /usr/local/bin
Installing app/dpdk-test-bbdev to /usr/local/bin
Installing app/dpdk-test-cmdline to /usr/local/bin
Installing app/dpdk-test-compress-perf to /usr/local/bin
Installing app/dpdk-test-crypto-perf to /usr/local/bin
Installing app/dpdk-test-dma-perf to /usr/local/bin
Installing app/dpdk-test-eventdev to /usr/local/bin
Installing app/dpdk-test-fib to /usr/local/bin
Installing app/dpdk-test-flow-perf to /usr/local/bin
Installing app/dpdk-test-gpudev to /usr/local/bin
Installing app/dpdk-test-mldev to /usr/local/bin
Installing app/dpdk-test-pipeline to /usr/local/bin
Installing app/dpdk-testpmd to /usr/local/bin
Installing app/dpdk-test-regex to /usr/local/bin
Installing app/dpdk-test-sad to /usr/local/bin
Installing app/dpdk-test-security-perf to /usr/local/bin
Installing app/dpdk-test to /usr/local/bin
Installing marvell-ci/test/cnxk-tests/common/pcap/pcap-pkt-cnt to /usr/local/bin/cnxk/common/pcap
Installing marvell-ci/test/cnxk-tests/common/pcap/pcap-len to /usr/local/bin/cnxk/common/pcap
Installing marvell-ci/test/cnxk-tests/common/pcap/pcap-mac to /usr/local/bin/cnxk/common/pcap
Installing marvell-ci/test/cnxk-tests/mempool_perf/cnxk_mempool_perf to /usr/local/bin/cnxk/mempool_perf
Installing marvell-ci/test/cnxk-tests/extbuf/cnxk-extbuf to /usr/local/bin/cnxk/extbuf
Installing marvell-ci/test/cnxk-tests/udp4-recv/udp4_recv_graph to /usr/local/bin/cnxk/udp4-recv
Installing marvell-ci/test/cnxk-tests/bphy_irq/bphy-irq to /usr/local/bin/cnxk/bphy_irq
Installing marvell-ci/test/cnxk-tests/mbuf_perf/mbuf-perf to /usr/local/bin/cnxk/mbuf_perf
Installing marvell-ci/test/cnxk-tests/l2fwd_event_pfc/l2fwd-event-pfc to /usr/local/bin/cnxk/l2fwd_event_pfc
Installing marvell-ci/test/cnxk-tests/multi_pool_pkt_tx/cnxk-multi_pool_pkt_tx to /usr/local/bin/cnxk/multi_pool_pkt_tx
Installing marvell-ci/test/cnxk-tests/ipsec_msns/cnxk_ipsec_msns to /usr/local/bin/cnxk/ipsec_msns
Installing marvell-ci/test/cnxk-tests/hwpool/cnxk-hwpool to /usr/local/bin/cnxk/hwpool
Installing marvell-ci/test/cnxk-tests/l3fwd_non_eal/l3fwd-non-eal to /usr/local/bin/cnxk/l3fwd
Installing marvell-ci/test/cnxk-tests/cpt_raw_test/cpt_raw_test to /usr/local/bin/cnxk/crypto
Installing /root/Helium_DPU/ET2500/dpdk-24.03/config/rte_config.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/log/rte_log.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/kvargs/rte_kvargs.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/argparse/rte_argparse.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/telemetry/rte_telemetry.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_atomic.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_byteorder.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_cpuflags.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_cycles.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_io.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_memcpy.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_pause.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_power_intrinsics.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_prefetch.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_rwlock.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_spinlock.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/generic/rte_vect.h to /usr/local/include/generic/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_atomic_32.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_atomic_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_atomic.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_byteorder.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_cpuflags_32.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_cpuflags_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_cpuflags.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_cycles_32.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_cycles_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_cycles.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_io_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_io.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_memcpy_32.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_memcpy_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_memcpy.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_pause_32.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_pause_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_pause.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_power_intrinsics.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_prefetch_32.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_prefetch_64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_prefetch.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_rwlock.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_spinlock.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/arm/include/rte_vect.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_alarm.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_bitmap.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_bitops.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_branch_prediction.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_bus.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_class.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_common.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_compat.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_debug.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_dev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_devargs.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_eal.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_eal_memconfig.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_eal_trace.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_errno.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_epoll.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_fbarray.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_hexdump.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_hypervisor.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_interrupts.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_keepalive.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_launch.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_lcore.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_lock_annotations.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_malloc.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_mcslock.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_memory.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_memzone.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_pci_dev_feature_defs.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_pci_dev_features.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_per_lcore.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_pflock.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_random.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_reciprocal.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_seqcount.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_seqlock.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_service.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_service_component.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_stdatomic.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_string_fns.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_tailq.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_thread.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_ticketlock.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_time.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_trace.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_trace_point.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_trace_point_register.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_uuid.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_version.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/include/rte_vfio.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eal/linux/include/rte_os.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_elem.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_elem_pvt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_c11_pvt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_generic_pvt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_hts.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_hts_elem_pvt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_peek.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_peek_elem_pvt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_peek_zc.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_rts.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ring/rte_ring_rts_elem_pvt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/rcu/rte_rcu_qsbr.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mempool/rte_mempool.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mempool/rte_mempool_trace_fp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mbuf/rte_mbuf.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mbuf/rte_mbuf_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mbuf/rte_mbuf_ptype.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mbuf/rte_mbuf_pool_ops.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mbuf/rte_mbuf_dyn.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_ip.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_tcp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_udp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_tls.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_dtls.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_esp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_sctp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_icmp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_arp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_ether.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_macsec.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_vxlan.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_gre.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_gtp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_net.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_net_crc.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_mpls.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_higig.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_ecpri.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_pdcp_hdr.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_geneve.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_l2tpv2.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_ppp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/net/rte_ib.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/meter/rte_meter.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_cman.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_ethdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_ethdev_trace_fp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_dev_info.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_flow.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_flow_driver.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_mtr.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_mtr_driver.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_tm.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_tm_driver.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_ethdev_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ethdev/rte_eth_ctrl.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pci/rte_pci.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_parse.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_parse_num.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_parse_ipaddr.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_parse_etheraddr.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_parse_string.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_rdline.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_vt100.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_socket.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_cirbuf.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cmdline/cmdline_parse_portlist.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/metrics/rte_metrics.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/metrics/rte_metrics_telemetry.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_fbk_hash.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_hash_crc.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_hash.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_jhash.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_thash.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_thash_gfni.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_crc_arm64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_crc_generic.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_crc_sw.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_crc_x86.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/hash/rte_thash_x86_gfni.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/timer/rte_timer.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/acl/rte_acl.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/acl/rte_acl_osdep.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bbdev/rte_bbdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bbdev/rte_bbdev_pmd.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bbdev/rte_bbdev_op.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bitratestats/rte_bitrate.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bpf/bpf_def.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bpf/rte_bpf.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/bpf/rte_bpf_ethdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cfgfile/rte_cfgfile.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/compressdev/rte_compressdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/compressdev/rte_comp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cryptodev/rte_cryptodev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cryptodev/rte_cryptodev_trace_fp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cryptodev/rte_crypto.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cryptodev/rte_crypto_sym.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cryptodev/rte_crypto_asym.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/cryptodev/rte_cryptodev_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/distributor/rte_distributor.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/dmadev/rte_dmadev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/dmadev/rte_dmadev_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/dmadev/rte_dmadev_trace_fp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/efd/rte_efd.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_event_crypto_adapter.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_event_dma_adapter.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_event_eth_rx_adapter.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_event_eth_tx_adapter.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_event_ring.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_event_timer_adapter.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_eventdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_eventdev_trace_fp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/eventdev/rte_eventdev_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/dispatcher/rte_dispatcher.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/gpudev/rte_gpudev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/gro/rte_gro.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/gso/rte_gso.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ip_frag/rte_ip_frag.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/jobstats/rte_jobstats.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/latencystats/rte_latencystats.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm6.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm_altivec.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm_neon.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm_scalar.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm_sse.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/lpm/rte_lpm_sve.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/member/rte_member.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pcapng/rte_pcapng.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/power/rte_power.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/power/rte_power_guest_channel.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/power/rte_power_pmd_mgmt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/power/rte_power_uncore.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/rawdev/rte_rawdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/rawdev/rte_rawdev_pmd.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/regexdev/rte_regexdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/regexdev/rte_regexdev_driver.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/regexdev/rte_regexdev_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mldev/rte_mldev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/mldev/rte_mldev_core.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/rib/rte_rib.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/rib/rte_rib6.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/reorder/rte_reorder.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/sched/rte_approx.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/sched/rte_red.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/sched/rte_sched.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/sched/rte_sched_common.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/sched/rte_pie.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/security/rte_security.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/security/rte_security_driver.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/stack/rte_stack.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/stack/rte_stack_std.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/stack/rte_stack_lf.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/stack/rte_stack_lf_generic.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/stack/rte_stack_lf_c11.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/stack/rte_stack_lf_stubs.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/vhost/rte_vdpa.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/vhost/rte_vhost.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/vhost/rte_vhost_async.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/vhost/rte_vhost_crypto.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ipsec/rte_ipsec.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ipsec/rte_ipsec_sa.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ipsec/rte_ipsec_sad.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/ipsec/rte_ipsec_group.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pdcp/rte_pdcp.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pdcp/rte_pdcp_group.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/fib/rte_fib.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/fib/rte_fib6.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_ethdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_fd.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_frag.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_ras.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_ring.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_sched.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_source_sink.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_sym_crypto.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_port_eventdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_swx_port.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_swx_port_ethdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_swx_port_fd.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_swx_port_ring.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/port/rte_swx_port_source_sink.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pdump/rte_pdump.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_lru.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_swx_hash_func.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_swx_table.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_swx_table_em.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_swx_table_learner.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_swx_table_selector.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_swx_table_wm.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_acl.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_array.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_hash.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_hash_cuckoo.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_hash_func.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_lpm.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_lpm_ipv6.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_stub.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_lru_arm64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_lru_x86.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/table/rte_table_hash_func_arm64.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_pipeline.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_port_in_action.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_table_action.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_swx_ipsec.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_swx_pipeline.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_swx_extern.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/pipeline/rte_swx_ctl.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/graph/rte_graph.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/graph/rte_graph_worker.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/graph/rte_graph_model_mcore_dispatch.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/graph/rte_graph_model_rtc.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/graph/rte_graph_worker_common.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/node/rte_node_eth_api.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/node/rte_node_ip4_api.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/node/rte_node_ip6_api.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/lib/node/rte_node_udp4_input_api.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/bus/pci/rte_bus_pci.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/bus/vdev/rte_bus_vdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/bus/vmbus/rte_bus_vmbus.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/bus/vmbus/rte_vmbus_reg.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/mempool/cnxk/rte_pmd_cnxk_mempool.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/mempool/dpaa2/rte_dpaa2_mempool.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/dma/dpaa2/rte_pmd_dpaa2_qdma.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/avp/rte_avp_common.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/avp/rte_avp_fifo.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/bnxt/rte_pmd_bnxt.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/bonding/rte_eth_bond.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/bonding/rte_eth_bond_8023ad.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/cnxk/rte_pmd_cnxk.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/dpaa/rte_pmd_dpaa.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/dpaa2/rte_pmd_dpaa2.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/i40e/rte_pmd_i40e.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/iavf/rte_pmd_iavf.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/ixgbe/rte_pmd_ixgbe.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/ring/rte_eth_ring.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/softnic/rte_eth_softnic.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/txgbe/rte_pmd_txgbe.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/net/vhost/rte_eth_vhost.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/raw/cnxk_bphy/rte_pmd_bphy.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/raw/cnxk_gpio/rte_pmd_cnxk_gpio.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/raw/dpaa2_cmdif/rte_pmd_dpaa2_cmdif.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/raw/ntb/rte_pmd_ntb.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/crypto/cnxk/rte_pmd_cnxk_crypto.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/crypto/scheduler/rte_cryptodev_scheduler.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/crypto/scheduler/rte_cryptodev_scheduler_operations.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/event/cnxk/rte_pmd_cnxk_eventdev.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/baseband/acc/rte_acc_cfg.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/drivers/baseband/fpga_5gnr_fec/rte_pmd_fpga_5gnr_fec.h to /usr/local/include/
Installing /root/Helium_DPU/ET2500/dpdk-24.03/buildtools/dpdk-cmdline-gen.py to /usr/local/bin
Installing /root/Helium_DPU/ET2500/dpdk-24.03/usertools/dpdk-devbind.py to /usr/local/bin
Installing /root/Helium_DPU/ET2500/dpdk-24.03/usertools/dpdk-pmdinfo.py to /usr/local/bin
Installing /root/Helium_DPU/ET2500/dpdk-24.03/usertools/dpdk-telemetry.py to /usr/local/bin
Installing /root/Helium_DPU/ET2500/dpdk-24.03/usertools/dpdk-hugepages.py to /usr/local/bin
Installing /root/Helium_DPU/ET2500/dpdk-24.03/usertools/dpdk-rss-flows.py to /usr/local/bin
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/scapy/sendrecv.py to /usr/local/bin/cnxk/common/scapy
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/scapy/createpcap.py to /usr/local/bin/cnxk/common/scapy
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/pcap/sample.pcap to /usr/local/bin/cnxk/common/pcap
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/pcap/pcap.env to /usr/local/bin/cnxk/common/pcap
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/testpmd/lbk.env to /usr/local/bin/cnxk/common/testpmd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/testpmd/pktgen.env to /usr/local/bin/cnxk/common/testpmd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/testpmd/common.env to /usr/local/bin/cnxk/common/testpmd
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/common/remote/command.env to /usr/local/bin/cnxk/common/remote
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/ptp_test/cnxk_ptp_test.sh to /usr/local/bin/cnxk/ptp_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/fwd_perf/cnxk_fwd_perf.sh to /usr/local/bin/cnxk/fwd_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/dma_perf/cnxk_dma_perf.sh to /usr/local/bin/cnxk/dma_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/crypto_perf/cnxk_crypto_perf.sh to /usr/local/bin/cnxk/crypto_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/event_perf/cnxk_event_perf.sh to /usr/local/bin/cnxk/event_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/ipsec_secgw/cnxk_ipsec_loopback.sh to /usr/local/bin/cnxk/ipsec_loopback
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/l2fwd_simple/cnxk_l2fwd_simple.sh to /usr/local/bin/cnxk/l2fwd_simple
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/ipsec_perf/cnxk_ipsec_perf.sh to /usr/local/bin/cnxk/ipsec_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/macsec_perf/cnxk_macsec_perf.sh to /usr/local/bin/cnxk/macsec_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/sample/cnxk_sample.sh to /usr/local/bin/cnxk/sample
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/tx_chksum/cnxk_tx_chksum.sh to /usr/local/bin/cnxk/tx_chksum
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/rx_chksum/cnxk_rx_chksum.sh to /usr/local/bin/cnxk/rx_chksum
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/dpdk_test/dpdk_test.sh to /usr/local/bin/cnxk/dpdk_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/port_ctrl/cnxk_port_ctrl.sh to /usr/local/bin/cnxk/port_ctrl
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/crypto_autotest/crypto_autotest.sh to /usr/local/bin/cnxk/crypto_autotest
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/inline_ipsec_autotest/inline_ipsec_autotest.sh to /usr/local/bin/cnxk/inline_ipsec_autotest
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/inline_macsec_autotest/inline_macsec_autotest.sh to /usr/local/bin/cnxk/inline_macsec_autotest
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/tm_test/cnxk_tm_test.sh to /usr/local/bin/cnxk/tm_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/flow_perf/cnxk_flow_perf.sh to /usr/local/bin/cnxk/flow_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/txrx_stats/cnxk_txrx_stats.sh to /usr/local/bin/cnxk/txrx_stats
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/flow_regression/cnxk_flow_regression.sh to /usr/local/bin/cnxk/flow_regression
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/cpt_2nd_pass_flow/cpt_2nd_pass_flow.sh to /usr/local/bin/cnxk/cpt_2nd_pass_flow
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/read_config/cnxk_read_config.sh to /usr/local/bin/cnxk/read_config
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/mempool_perf/cnxk_mempool_perf.sh to /usr/local/bin/cnxk/mempool_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/mac_test/cnxk_mac_test.sh to /usr/local/bin/cnxk/mac_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/extbuf/cnxk_extbuf.sh to /usr/local/bin/cnxk/extbuf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/extbuf/cnxk_indirectbuf.sh to /usr/local/bin/cnxk/extbuf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/gpio_test/cnxk_gpio_test.sh to /usr/local/bin/cnxk/gpio_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/meter_test/cnxk_mtr_test.sh to /usr/local/bin/cnxk/meter_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/bphy_irq/bphy_irq.sh to /usr/local/bin/cnxk/bphy_irq
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/queue_intr_test/cnxk_q_intr_test.sh to /usr/local/bin/cnxk/q_intr_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/dpdk_config_test/dpdk_config_test.sh to /usr/local/bin/cnxk/dpdk_config_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/trace_autotest/trace_autotest.sh to /usr/local/bin/cnxk/trace_autotest
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/hotplug_test/cnxk_hotplug_test.sh to /usr/local/bin/cnxk/hotplug_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/tx_vlan/cnxk_tx_vlan.sh to /usr/local/bin/cnxk/tx_vlan
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/ipsec_reassembly_perf/cnxk_ipsec_reassembly_perf.sh to /usr/local/bin/cnxk/ipsec_reassembly_perf
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/lso_test/cnxk_lso_test.sh to /usr/local/bin/cnxk/lso_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/cman_test/cnxk_cman_test.sh to /usr/local/bin/cnxk/cman_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/multi_pool_pkt_tx/cnxk_multi_pool_pkt_tx.sh to /usr/local/bin/cnxk/multi_pool_pkt_tx
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/flow_ctrl/cnxk_fc_test.sh to /usr/local/bin/cnxk/cman_test
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/multi_mempool/cnxk_multi_mempool.sh to /usr/local/bin/cnxk/multi_mempool
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/ipsec_msns/cnxk_ipsec_msns.sh to /usr/local/bin/cnxk/ipsec_msns
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/policer_test/cnxk_ingress_policer.sh to /usr/local/bin/cnxk/ingress_policer
Installing /root/Helium_DPU/ET2500/dpdk-24.03/marvell-ci/test/cnxk-tests/flow_aging/cnxk_flow_aging.sh to /usr/local/bin/cnxk/flow_aging
Installing /root/Helium_DPU/ET2500/dpdk-24.03/build/rte_build_config.h to /usr/local/include
Installing /root/Helium_DPU/ET2500/dpdk-24.03/build/meson-private/libdpdk-libs.pc to /usr/local/lib/aarch64-linux-gnu/pkgconfig
Installing /root/Helium_DPU/ET2500/dpdk-24.03/build/meson-private/libdpdk.pc to /usr/local/lib/aarch64-linux-gnu/pkgconfig
Installing symlink pointing to librte_log.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_log.so.24
Installing symlink pointing to librte_log.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_log.so
Installing symlink pointing to librte_kvargs.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_kvargs.so.24
Installing symlink pointing to librte_kvargs.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_kvargs.so
Installing symlink pointing to librte_argparse.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_argparse.so.24
Installing symlink pointing to librte_argparse.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_argparse.so
Installing symlink pointing to librte_telemetry.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_telemetry.so.24
Installing symlink pointing to librte_telemetry.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_telemetry.so
Installing symlink pointing to librte_eal.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_eal.so.24
Installing symlink pointing to librte_eal.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_eal.so
Installing symlink pointing to librte_ring.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_ring.so.24
Installing symlink pointing to librte_ring.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_ring.so
Installing symlink pointing to librte_rcu.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_rcu.so.24
Installing symlink pointing to librte_rcu.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_rcu.so
Installing symlink pointing to librte_mempool.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_mempool.so.24
Installing symlink pointing to librte_mempool.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_mempool.so
Installing symlink pointing to librte_mbuf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_mbuf.so.24
Installing symlink pointing to librte_mbuf.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_mbuf.so
Installing symlink pointing to librte_net.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_net.so.24
Installing symlink pointing to librte_net.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_net.so
Installing symlink pointing to librte_meter.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_meter.so.24
Installing symlink pointing to librte_meter.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_meter.so
Installing symlink pointing to librte_ethdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_ethdev.so.24
Installing symlink pointing to librte_ethdev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_ethdev.so
Installing symlink pointing to librte_pci.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_pci.so.24
Installing symlink pointing to librte_pci.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_pci.so
Installing symlink pointing to librte_cmdline.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_cmdline.so.24
Installing symlink pointing to librte_cmdline.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_cmdline.so
Installing symlink pointing to librte_metrics.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_metrics.so.24
Installing symlink pointing to librte_metrics.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_metrics.so
Installing symlink pointing to librte_hash.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_hash.so.24
Installing symlink pointing to librte_hash.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_hash.so
Installing symlink pointing to librte_timer.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_timer.so.24
Installing symlink pointing to librte_timer.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_timer.so
Installing symlink pointing to librte_acl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_acl.so.24
Installing symlink pointing to librte_acl.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_acl.so
Installing symlink pointing to librte_bbdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_bbdev.so.24
Installing symlink pointing to librte_bbdev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_bbdev.so
Installing symlink pointing to librte_bitratestats.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_bitratestats.so.24
Installing symlink pointing to librte_bitratestats.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_bitratestats.so
Installing symlink pointing to librte_bpf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_bpf.so.24
Installing symlink pointing to librte_bpf.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_bpf.so
Installing symlink pointing to librte_cfgfile.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_cfgfile.so.24
Installing symlink pointing to librte_cfgfile.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_cfgfile.so
Installing symlink pointing to librte_compressdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_compressdev.so.24
Installing symlink pointing to librte_compressdev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_compressdev.so
Installing symlink pointing to librte_cryptodev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_cryptodev.so.24
Installing symlink pointing to librte_cryptodev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_cryptodev.so
Installing symlink pointing to librte_distributor.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_distributor.so.24
Installing symlink pointing to librte_distributor.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_distributor.so
Installing symlink pointing to librte_dmadev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_dmadev.so.24
Installing symlink pointing to librte_dmadev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_dmadev.so
Installing symlink pointing to librte_efd.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_efd.so.24
Installing symlink pointing to librte_efd.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_efd.so
Installing symlink pointing to librte_eventdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_eventdev.so.24
Installing symlink pointing to librte_eventdev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_eventdev.so
Installing symlink pointing to librte_dispatcher.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_dispatcher.so.24
Installing symlink pointing to librte_dispatcher.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_dispatcher.so
Installing symlink pointing to librte_gpudev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_gpudev.so.24
Installing symlink pointing to librte_gpudev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_gpudev.so
Installing symlink pointing to librte_gro.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_gro.so.24
Installing symlink pointing to librte_gro.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_gro.so
Installing symlink pointing to librte_gso.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_gso.so.24
Installing symlink pointing to librte_gso.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_gso.so
Installing symlink pointing to librte_ip_frag.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_ip_frag.so.24
Installing symlink pointing to librte_ip_frag.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_ip_frag.so
Installing symlink pointing to librte_jobstats.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_jobstats.so.24
Installing symlink pointing to librte_jobstats.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_jobstats.so
Installing symlink pointing to librte_latencystats.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_latencystats.so.24
Installing symlink pointing to librte_latencystats.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_latencystats.so
Installing symlink pointing to librte_lpm.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_lpm.so.24
Installing symlink pointing to librte_lpm.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_lpm.so
Installing symlink pointing to librte_member.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_member.so.24
Installing symlink pointing to librte_member.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_member.so
Installing symlink pointing to librte_pcapng.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_pcapng.so.24
Installing symlink pointing to librte_pcapng.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_pcapng.so
Installing symlink pointing to librte_power.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_power.so.24
Installing symlink pointing to librte_power.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_power.so
Installing symlink pointing to librte_rawdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_rawdev.so.24
Installing symlink pointing to librte_rawdev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_rawdev.so
Installing symlink pointing to librte_regexdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_regexdev.so.24
Installing symlink pointing to librte_regexdev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_regexdev.so
Installing symlink pointing to librte_mldev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_mldev.so.24
Installing symlink pointing to librte_mldev.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_mldev.so
Installing symlink pointing to librte_rib.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_rib.so.24
Installing symlink pointing to librte_rib.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_rib.so
Installing symlink pointing to librte_reorder.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_reorder.so.24
Installing symlink pointing to librte_reorder.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_reorder.so
Installing symlink pointing to librte_sched.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_sched.so.24
Installing symlink pointing to librte_sched.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_sched.so
Installing symlink pointing to librte_security.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_security.so.24
Installing symlink pointing to librte_security.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_security.so
Installing symlink pointing to librte_stack.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_stack.so.24
Installing symlink pointing to librte_stack.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_stack.so
Installing symlink pointing to librte_vhost.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_vhost.so.24
Installing symlink pointing to librte_vhost.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_vhost.so
Installing symlink pointing to librte_ipsec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_ipsec.so.24
Installing symlink pointing to librte_ipsec.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_ipsec.so
Installing symlink pointing to librte_pdcp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_pdcp.so.24
Installing symlink pointing to librte_pdcp.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_pdcp.so
Installing symlink pointing to librte_fib.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_fib.so.24
Installing symlink pointing to librte_fib.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_fib.so
Installing symlink pointing to librte_port.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_port.so.24
Installing symlink pointing to librte_port.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_port.so
Installing symlink pointing to librte_pdump.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_pdump.so.24
Installing symlink pointing to librte_pdump.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_pdump.so
Installing symlink pointing to librte_table.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_table.so.24
Installing symlink pointing to librte_table.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_table.so
Installing symlink pointing to librte_pipeline.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_pipeline.so.24
Installing symlink pointing to librte_pipeline.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_pipeline.so
Installing symlink pointing to librte_graph.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_graph.so.24
Installing symlink pointing to librte_graph.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_graph.so
Installing symlink pointing to librte_node.so.24.1 to /usr/local/lib/aarch64-linux-gnu/librte_node.so.24
Installing symlink pointing to librte_node.so.24 to /usr/local/lib/aarch64-linux-gnu/librte_node.so
Installing symlink pointing to librte_common_cpt.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_cpt.so.24
Installing symlink pointing to librte_common_cpt.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_cpt.so
Installing symlink pointing to librte_common_dpaax.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_dpaax.so.24
Installing symlink pointing to librte_common_dpaax.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_dpaax.so
Installing symlink pointing to librte_common_iavf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_iavf.so.24
Installing symlink pointing to librte_common_iavf.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_iavf.so
Installing symlink pointing to librte_common_idpf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_idpf.so.24
Installing symlink pointing to librte_common_idpf.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_idpf.so
Installing symlink pointing to librte_common_ionic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_ionic.so.24
Installing symlink pointing to librte_common_ionic.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_ionic.so
Installing symlink pointing to librte_common_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_octeontx.so.24
Installing symlink pointing to librte_common_octeontx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_octeontx.so
Installing symlink pointing to librte_bus_auxiliary.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_auxiliary.so.24
Installing symlink pointing to librte_bus_auxiliary.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_auxiliary.so
Installing symlink pointing to librte_bus_cdx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_cdx.so.24
Installing symlink pointing to librte_bus_cdx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_cdx.so
Installing symlink pointing to librte_bus_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_dpaa.so.24
Installing symlink pointing to librte_bus_dpaa.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_dpaa.so
Installing symlink pointing to librte_bus_fslmc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_fslmc.so.24
Installing symlink pointing to librte_bus_fslmc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_fslmc.so
Installing symlink pointing to librte_bus_ifpga.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_ifpga.so.24
Installing symlink pointing to librte_bus_ifpga.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_ifpga.so
Installing symlink pointing to librte_bus_pci.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_pci.so.24
Installing symlink pointing to librte_bus_pci.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_pci.so
Installing symlink pointing to librte_bus_platform.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_platform.so.24
Installing symlink pointing to librte_bus_platform.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_platform.so
Installing symlink pointing to librte_bus_uacce.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_uacce.so.24
Installing symlink pointing to librte_bus_uacce.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_uacce.so
Installing symlink pointing to librte_bus_vdev.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_vdev.so.24
Installing symlink pointing to librte_bus_vdev.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_vdev.so
Installing symlink pointing to librte_bus_vmbus.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_vmbus.so.24
Installing symlink pointing to librte_bus_vmbus.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_bus_vmbus.so
Installing symlink pointing to librte_common_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_cnxk.so.24
Installing symlink pointing to librte_common_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_cnxk.so
Installing symlink pointing to librte_common_nfp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_nfp.so.24
Installing symlink pointing to librte_common_nfp.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_nfp.so
Installing symlink pointing to librte_common_nitrox.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_nitrox.so.24
Installing symlink pointing to librte_common_nitrox.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_nitrox.so
Installing symlink pointing to librte_common_qat.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_qat.so.24
Installing symlink pointing to librte_common_qat.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_qat.so
Installing symlink pointing to librte_common_sfc_efx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_sfc_efx.so.24
Installing symlink pointing to librte_common_sfc_efx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_common_sfc_efx.so
Installing symlink pointing to librte_mempool_bucket.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_bucket.so.24
Installing symlink pointing to librte_mempool_bucket.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_bucket.so
Installing symlink pointing to librte_mempool_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_cnxk.so.24
Installing symlink pointing to librte_mempool_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_cnxk.so
Installing symlink pointing to librte_mempool_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_dpaa.so.24
Installing symlink pointing to librte_mempool_dpaa.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_dpaa.so
Installing symlink pointing to librte_mempool_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_dpaa2.so.24
Installing symlink pointing to librte_mempool_dpaa2.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_dpaa2.so
Installing symlink pointing to librte_mempool_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_octeontx.so.24
Installing symlink pointing to librte_mempool_octeontx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_octeontx.so
Installing symlink pointing to librte_mempool_ring.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_ring.so.24
Installing symlink pointing to librte_mempool_ring.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_ring.so
Installing symlink pointing to librte_mempool_stack.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_stack.so.24
Installing symlink pointing to librte_mempool_stack.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_mempool_stack.so
Installing symlink pointing to librte_dma_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_cnxk.so.24
Installing symlink pointing to librte_dma_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_cnxk.so
Installing symlink pointing to librte_dma_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_dpaa.so.24
Installing symlink pointing to librte_dma_dpaa.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_dpaa.so
Installing symlink pointing to librte_dma_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_dpaa2.so.24
Installing symlink pointing to librte_dma_dpaa2.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_dpaa2.so
Installing symlink pointing to librte_dma_hisilicon.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_hisilicon.so.24
Installing symlink pointing to librte_dma_hisilicon.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_hisilicon.so
Installing symlink pointing to librte_dma_odm.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_odm.so.24
Installing symlink pointing to librte_dma_odm.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_odm.so
Installing symlink pointing to librte_dma_skeleton.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_skeleton.so.24
Installing symlink pointing to librte_dma_skeleton.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_dma_skeleton.so
Installing symlink pointing to librte_net_af_packet.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_af_packet.so.24
Installing symlink pointing to librte_net_af_packet.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_af_packet.so
Installing symlink pointing to librte_net_ark.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ark.so.24
Installing symlink pointing to librte_net_ark.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ark.so
Installing symlink pointing to librte_net_atlantic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_atlantic.so.24
Installing symlink pointing to librte_net_atlantic.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_atlantic.so
Installing symlink pointing to librte_net_avp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_avp.so.24
Installing symlink pointing to librte_net_avp.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_avp.so
Installing symlink pointing to librte_net_axgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_axgbe.so.24
Installing symlink pointing to librte_net_axgbe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_axgbe.so
Installing symlink pointing to librte_net_bnx2x.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_bnx2x.so.24
Installing symlink pointing to librte_net_bnx2x.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_bnx2x.so
Installing symlink pointing to librte_net_bnxt.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_bnxt.so.24
Installing symlink pointing to librte_net_bnxt.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_bnxt.so
Installing symlink pointing to librte_net_bond.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_bond.so.24
Installing symlink pointing to librte_net_bond.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_bond.so
Installing symlink pointing to librte_net_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_cnxk.so.24
Installing symlink pointing to librte_net_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_cnxk.so
Installing symlink pointing to librte_net_cpfl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_cpfl.so.24
Installing symlink pointing to librte_net_cpfl.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_cpfl.so
Installing symlink pointing to librte_net_cxgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_cxgbe.so.24
Installing symlink pointing to librte_net_cxgbe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_cxgbe.so
Installing symlink pointing to librte_net_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_dpaa.so.24
Installing symlink pointing to librte_net_dpaa.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_dpaa.so
Installing symlink pointing to librte_net_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_dpaa2.so.24
Installing symlink pointing to librte_net_dpaa2.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_dpaa2.so
Installing symlink pointing to librte_net_e1000.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_e1000.so.24
Installing symlink pointing to librte_net_e1000.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_e1000.so
Installing symlink pointing to librte_net_ena.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ena.so.24
Installing symlink pointing to librte_net_ena.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ena.so
Installing symlink pointing to librte_net_enetc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_enetc.so.24
Installing symlink pointing to librte_net_enetc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_enetc.so
Installing symlink pointing to librte_net_enetfec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_enetfec.so.24
Installing symlink pointing to librte_net_enetfec.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_enetfec.so
Installing symlink pointing to librte_net_enic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_enic.so.24
Installing symlink pointing to librte_net_enic.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_enic.so
Installing symlink pointing to librte_net_failsafe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_failsafe.so.24
Installing symlink pointing to librte_net_failsafe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_failsafe.so
Installing symlink pointing to librte_net_fm10k.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_fm10k.so.24
Installing symlink pointing to librte_net_fm10k.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_fm10k.so
Installing symlink pointing to librte_net_gve.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_gve.so.24
Installing symlink pointing to librte_net_gve.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_gve.so
Installing symlink pointing to librte_net_hinic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_hinic.so.24
Installing symlink pointing to librte_net_hinic.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_hinic.so
Installing symlink pointing to librte_net_hns3.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_hns3.so.24
Installing symlink pointing to librte_net_hns3.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_hns3.so
Installing symlink pointing to librte_net_i40e.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_i40e.so.24
Installing symlink pointing to librte_net_i40e.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_i40e.so
Installing symlink pointing to librte_net_iavf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_iavf.so.24
Installing symlink pointing to librte_net_iavf.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_iavf.so
Installing symlink pointing to librte_net_ice.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ice.so.24
Installing symlink pointing to librte_net_ice.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ice.so
Installing symlink pointing to librte_net_idpf.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_idpf.so.24
Installing symlink pointing to librte_net_idpf.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_idpf.so
Installing symlink pointing to librte_net_igc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_igc.so.24
Installing symlink pointing to librte_net_igc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_igc.so
Installing symlink pointing to librte_net_ionic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ionic.so.24
Installing symlink pointing to librte_net_ionic.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ionic.so
Installing symlink pointing to librte_net_ixgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ixgbe.so.24
Installing symlink pointing to librte_net_ixgbe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ixgbe.so
Installing symlink pointing to librte_net_memif.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_memif.so.24
Installing symlink pointing to librte_net_memif.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_memif.so
Installing symlink pointing to librte_net_netvsc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_netvsc.so.24
Installing symlink pointing to librte_net_netvsc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_netvsc.so
Installing symlink pointing to librte_net_nfp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_nfp.so.24
Installing symlink pointing to librte_net_nfp.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_nfp.so
Installing symlink pointing to librte_net_ngbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ngbe.so.24
Installing symlink pointing to librte_net_ngbe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ngbe.so
Installing symlink pointing to librte_net_null.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_null.so.24
Installing symlink pointing to librte_net_null.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_null.so
Installing symlink pointing to librte_net_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_octeontx.so.24
Installing symlink pointing to librte_net_octeontx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_octeontx.so
Installing symlink pointing to librte_net_octeon_ep.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_octeon_ep.so.24
Installing symlink pointing to librte_net_octeon_ep.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_octeon_ep.so
Installing symlink pointing to librte_net_pcap.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_pcap.so.24
Installing symlink pointing to librte_net_pcap.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_pcap.so
Installing symlink pointing to librte_net_pfe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_pfe.so.24
Installing symlink pointing to librte_net_pfe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_pfe.so
Installing symlink pointing to librte_net_qede.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_qede.so.24
Installing symlink pointing to librte_net_qede.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_qede.so
Installing symlink pointing to librte_net_ring.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ring.so.24
Installing symlink pointing to librte_net_ring.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_ring.so
Installing symlink pointing to librte_net_sfc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_sfc.so.24
Installing symlink pointing to librte_net_sfc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_sfc.so
Installing symlink pointing to librte_net_softnic.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_softnic.so.24
Installing symlink pointing to librte_net_softnic.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_softnic.so
Installing symlink pointing to librte_net_tap.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_tap.so.24
Installing symlink pointing to librte_net_tap.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_tap.so
Installing symlink pointing to librte_net_thunderx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_thunderx.so.24
Installing symlink pointing to librte_net_thunderx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_thunderx.so
Installing symlink pointing to librte_net_txgbe.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_txgbe.so.24
Installing symlink pointing to librte_net_txgbe.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_txgbe.so
Installing symlink pointing to librte_net_vdev_netvsc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_vdev_netvsc.so.24
Installing symlink pointing to librte_net_vdev_netvsc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_vdev_netvsc.so
Installing symlink pointing to librte_net_vhost.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_vhost.so.24
Installing symlink pointing to librte_net_vhost.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_vhost.so
Installing symlink pointing to librte_net_virtio.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_virtio.so.24
Installing symlink pointing to librte_net_virtio.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_virtio.so
Installing symlink pointing to librte_net_vmxnet3.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_vmxnet3.so.24
Installing symlink pointing to librte_net_vmxnet3.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_net_vmxnet3.so
Installing symlink pointing to librte_raw_cnxk_bphy.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_cnxk_bphy.so.24
Installing symlink pointing to librte_raw_cnxk_bphy.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_cnxk_bphy.so
Installing symlink pointing to librte_raw_cnxk_gpio.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_cnxk_gpio.so.24
Installing symlink pointing to librte_raw_cnxk_gpio.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_cnxk_gpio.so
Installing symlink pointing to librte_raw_dpaa2_cmdif.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_dpaa2_cmdif.so.24
Installing symlink pointing to librte_raw_dpaa2_cmdif.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_dpaa2_cmdif.so
Installing symlink pointing to librte_raw_ntb.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_ntb.so.24
Installing symlink pointing to librte_raw_ntb.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_ntb.so
Installing symlink pointing to librte_raw_skeleton.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_skeleton.so.24
Installing symlink pointing to librte_raw_skeleton.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_raw_skeleton.so
Installing symlink pointing to librte_crypto_bcmfs.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_bcmfs.so.24
Installing symlink pointing to librte_crypto_bcmfs.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_bcmfs.so
Installing symlink pointing to librte_crypto_caam_jr.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_caam_jr.so.24
Installing symlink pointing to librte_crypto_caam_jr.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_caam_jr.so
Installing symlink pointing to librte_crypto_ccp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_ccp.so.24
Installing symlink pointing to librte_crypto_ccp.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_ccp.so
Installing symlink pointing to librte_crypto_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_cnxk.so.24
Installing symlink pointing to librte_crypto_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_cnxk.so
Installing symlink pointing to librte_crypto_dpaa_sec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_dpaa_sec.so.24
Installing symlink pointing to librte_crypto_dpaa_sec.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_dpaa_sec.so
Installing symlink pointing to librte_crypto_dpaa2_sec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_dpaa2_sec.so.24
Installing symlink pointing to librte_crypto_dpaa2_sec.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_dpaa2_sec.so
Installing symlink pointing to librte_crypto_nitrox.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_nitrox.so.24
Installing symlink pointing to librte_crypto_nitrox.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_nitrox.so
Installing symlink pointing to librte_crypto_null.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_null.so.24
Installing symlink pointing to librte_crypto_null.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_null.so
Installing symlink pointing to librte_crypto_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_octeontx.so.24
Installing symlink pointing to librte_crypto_octeontx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_octeontx.so
Installing symlink pointing to librte_crypto_openssl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_openssl.so.24
Installing symlink pointing to librte_crypto_openssl.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_openssl.so
Installing symlink pointing to librte_crypto_scheduler.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_scheduler.so.24
Installing symlink pointing to librte_crypto_scheduler.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_scheduler.so
Installing symlink pointing to librte_crypto_virtio.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_virtio.so.24
Installing symlink pointing to librte_crypto_virtio.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_crypto_virtio.so
Installing symlink pointing to librte_compress_nitrox.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_compress_nitrox.so.24
Installing symlink pointing to librte_compress_nitrox.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_compress_nitrox.so
Installing symlink pointing to librte_compress_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_compress_octeontx.so.24
Installing symlink pointing to librte_compress_octeontx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_compress_octeontx.so
Installing symlink pointing to librte_compress_zlib.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_compress_zlib.so.24
Installing symlink pointing to librte_compress_zlib.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_compress_zlib.so
Installing symlink pointing to librte_regex_cn9k.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_regex_cn9k.so.24
Installing symlink pointing to librte_regex_cn9k.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_regex_cn9k.so
Installing symlink pointing to librte_ml_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_ml_cnxk.so.24
Installing symlink pointing to librte_ml_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_ml_cnxk.so
Installing symlink pointing to librte_vdpa_ifc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_vdpa_ifc.so.24
Installing symlink pointing to librte_vdpa_ifc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_vdpa_ifc.so
Installing symlink pointing to librte_vdpa_nfp.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_vdpa_nfp.so.24
Installing symlink pointing to librte_vdpa_nfp.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_vdpa_nfp.so
Installing symlink pointing to librte_vdpa_sfc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_vdpa_sfc.so.24
Installing symlink pointing to librte_vdpa_sfc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_vdpa_sfc.so
Installing symlink pointing to librte_event_cnxk.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_cnxk.so.24
Installing symlink pointing to librte_event_cnxk.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_cnxk.so
Installing symlink pointing to librte_event_dpaa.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_dpaa.so.24
Installing symlink pointing to librte_event_dpaa.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_dpaa.so
Installing symlink pointing to librte_event_dpaa2.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_dpaa2.so.24
Installing symlink pointing to librte_event_dpaa2.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_dpaa2.so
Installing symlink pointing to librte_event_dsw.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_dsw.so.24
Installing symlink pointing to librte_event_dsw.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_dsw.so
Installing symlink pointing to librte_event_opdl.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_opdl.so.24
Installing symlink pointing to librte_event_opdl.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_opdl.so
Installing symlink pointing to librte_event_skeleton.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_skeleton.so.24
Installing symlink pointing to librte_event_skeleton.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_skeleton.so
Installing symlink pointing to librte_event_sw.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_sw.so.24
Installing symlink pointing to librte_event_sw.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_sw.so
Installing symlink pointing to librte_event_octeontx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_octeontx.so.24
Installing symlink pointing to librte_event_octeontx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_event_octeontx.so
Installing symlink pointing to librte_baseband_acc.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_acc.so.24
Installing symlink pointing to librte_baseband_acc.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_acc.so
Installing symlink pointing to librte_baseband_fpga_5gnr_fec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_fpga_5gnr_fec.so.24
Installing symlink pointing to librte_baseband_fpga_5gnr_fec.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_fpga_5gnr_fec.so
Installing symlink pointing to librte_baseband_fpga_lte_fec.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_fpga_lte_fec.so.24
Installing symlink pointing to librte_baseband_fpga_lte_fec.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_fpga_lte_fec.so
Installing symlink pointing to librte_baseband_la12xx.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_la12xx.so.24
Installing symlink pointing to librte_baseband_la12xx.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_la12xx.so
Installing symlink pointing to librte_baseband_null.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_null.so.24
Installing symlink pointing to librte_baseband_null.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_null.so
Installing symlink pointing to librte_baseband_turbo_sw.so.24.1 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_turbo_sw.so.24
Installing symlink pointing to librte_baseband_turbo_sw.so.24 to /usr/local/lib/aarch64-linux-gnu/dpdk/pmds-24.1/librte_baseband_turbo_sw.so
Running custom install script '/bin/sh /root/Helium_DPU/ET2500/dpdk-24.03/config/../buildtools/symlink-drivers-solibs.sh lib/aarch64-linux-gnu dpdk/pmds-24.1'
```





