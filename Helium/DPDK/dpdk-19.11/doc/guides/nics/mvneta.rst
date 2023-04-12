..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Marvell International Ltd.
    Copyright(c) 2018 Semihalf.
    All rights reserved.

.. _mvneta_poll_mode_driver:

MVNETA Poll Mode Driver
=======================

The MVNETA PMD (librte_pmd_mvneta) provides poll mode driver support
for the Marvell NETA 1/2.5 Gbps adapter.

Detailed information about SoCs that use PPv2 can be obtained here:

* https://www.marvell.com/embedded-processors/armada-3700/

Features
--------

Features of the MVNETA PMD are:

- Start/stop
- tx/rx_queue_setup
- tx/rx_burst
- Speed capabilities
- Jumbo frame
- MTU update
- Jumbo frame
- Promiscuous mode
- Unicast MAC filter
- Link status
- CRC offload
- L3 checksum offload
- L4 checksum offload
- Packet type parsing
- Basic stats
- Multicast MAC filter
- Scattered TX frames


Limitations
-----------

- Flushing vlans added for filtering is not possible due to MUSDK missing
  functionality. Current workaround is to reset board so that NETA has a
  chance to start in a sane state.

- MUSDK architecture does not support changing configuration in run time.
  All nessesary configurations should be done before first dev_start().

- Running more than one DPDK-MUSDK application simultaneously is not supported.

Prerequisites
-------------

- Linux Kernel sources
- MUSDK (Marvell User-Space SDK) sources

  MUSDK is a light-weight library that provides direct access to Marvell's
  NETA. Alternatively prebuilt MUSDK library can be
  requested from `Marvell Extranet <https://extranet.marvell.com>`_. Once
  approval has been granted, library can be found by typing ``musdk`` in
  the search box.

  To better understand the library, please consult documentation
  available in the ``doc`` top level directory of the MUSDK sources.

- DPDK environment

  Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup
  DPDK environment.

Pre-Installation Configuration
------------------------------

Config File Options
~~~~~~~~~~~~~~~~~~~

The following options can be modified in the ``config`` file.
Please note that enabling debugging options may affect system performance.

- ``CONFIG_RTE_LIBRTE_MVNETA_PMD`` (default ``n``)

  By default it is enabled only for defconfig_arm64-armada-* config.
  Toggle compilation of the ``librte_pmd_mvneta`` driver.

- ``CONFIG_RTE_LIBRTE_MVEP_COMMON`` (default ``n``)

  By default it is enabled only for defconfig_arm64-armada-* config.
  Toggle compilation of the Marvell common utils.
  Must be enabled for Marvell PMDs.

Building DPDK
-------------

Driver needs precompiled MUSDK library during compilation.
MUSDK will be installed to `usr/local` under current directory.
For the detailed build instructions please consult ``doc/musdk_get_started.txt``.

Before the DPDK build process the environmental variable ``LIBMUSDK_PATH`` with
the path to the MUSDK installation directory needs to be exported.

For additional instructions regarding DPDK cross compilation please refer to :doc:`Cross compile DPDK for ARM64 <../linux_gsg/cross_build_dpdk_for_arm64>`.

.. code-block:: console

   export LIBMUSDK_PATH=<musdk>/usr/local
   make config T=arm64-armada-linuxapp-gcc
   make

Usage Example
-------------

MVNETA PMD requires extra out of tree kernel modules to function properly.
Please consult ``doc/musdk_get_started.txt`` for the detailed build instructions.

.. code-block:: console

   insmod musdk_cma.ko
   insmod uio_pdrv_genirq.ko of_id="generic-uio"

Additionally interfaces used by DPDK application need to be put up:

.. code-block:: console

   ip link set eth0 up
   ip link set eth1 up

In order to run testpmd example application following command can be used:

.. code-block:: console

   ./testpmd --vdev=net_mvneta,iface=eth0,iface=eth1 -c 3 -- \
   --burst=20 --txd=512 --rxd=512 --rxq=1 --txq=1  --nb-cores=1 -i -a


In order to run l2fwd example application following command can be used:

.. code-block:: console

   ./l2fwd --vdev=eth_mvneta,iface=eth0,iface=eth1 -c 3 -- -T 1 -p 3

In order to run l2fwd example application following command can be used:

.. code-block:: console

   ./l3fwd --vdev=eth_mvneta,iface=eth0,iface=eth1 -c 2 -- -P -p 3 -L --config="(0,0,1),(1,0,1)"
