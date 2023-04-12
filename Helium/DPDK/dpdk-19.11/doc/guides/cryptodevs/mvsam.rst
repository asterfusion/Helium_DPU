..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Marvell International Ltd.
    Copyright(c) 2018 Semihalf.
    All rights reserved.

MVSAM Crypto Poll Mode Driver
=============================

The MVSAM CRYPTO PMD (**librte_crypto_mvsam_pmd**) provides poll mode crypto driver
support by utilizing MUSDK library, which provides cryptographic operations
acceleration by using Security Acceleration Engine (EIP197) directly from
user-space with minimum overhead and high performance.

Detailed information about SoCs that use MVSAM crypto driver can be obtained here:

* https://www.marvell.com/embedded-processors/armada-70xx/
* https://www.marvell.com/embedded-processors/armada-80xx/
* https://www.marvell.com/embedded-processors/armada-3700/


Features
--------

MVSAM CRYPTO PMD has support for:

Features:

* Symmetric crypto operations: encryption/description and authentication
* Symmetric chaining crypto operations
* HW Accelerated using EIP97/EIP197b/EIP197d
* Out-of-place Scatter-gather list Input, Linear Buffers Output
* Out-of-place Linear Buffers Input, Linear Buffers Output


Cipher algorithms:

* ``RTE_CRYPTO_CIPHER_NULL``
* ``RTE_CRYPTO_CIPHER_AES_CBC``
* ``RTE_CRYPTO_CIPHER_AES_CTR``
* ``RTE_CRYPTO_CIPHER_AES_ECB``
* ``RTE_CRYPTO_CIPHER_3DES_CBC``
* ``RTE_CRYPTO_CIPHER_3DES_CTR``
* ``RTE_CRYPTO_CIPHER_3DES_ECB``

Hash algorithms:

* ``RTE_CRYPTO_AUTH_NULL``
* ``RTE_CRYPTO_AUTH_MD5``
* ``RTE_CRYPTO_AUTH_MD5_HMAC``
* ``RTE_CRYPTO_AUTH_SHA1``
* ``RTE_CRYPTO_AUTH_SHA1_HMAC``
* ``RTE_CRYPTO_AUTH_SHA224``
* ``RTE_CRYPTO_AUTH_SHA224_HMAC``
* ``RTE_CRYPTO_AUTH_SHA256``
* ``RTE_CRYPTO_AUTH_SHA256_HMAC``
* ``RTE_CRYPTO_AUTH_SHA384``
* ``RTE_CRYPTO_AUTH_SHA384_HMAC``
* ``RTE_CRYPTO_AUTH_SHA512``
* ``RTE_CRYPTO_AUTH_SHA512_HMAC``
* ``RTE_CRYPTO_AUTH_AES_GMAC``

AEAD algorithms:

* ``RTE_CRYPTO_AEAD_AES_GCM``

For supported feature flags please consult :doc:`overview`.

Limitations
-----------

* Hardware only supports scenarios where ICV (digest buffer) is placed just
  after the authenticated data. Other placement will result in error.

Installation
------------

The following options can be modified in the ``config`` file.
Please note that enabling debugging options may affect system performance.

- ``CONFIG_RTE_LIBRTE_PMD_MVSAM_CRYPTO`` (default: ``n``)

  By default it is enabled only for defconfig_arm64-armada-* config.
  Toggle compilation of the ``librte_pmd_mvsam`` driver.

- ``CONFIG_RTE_LIBRTE_PMD_MVSAM_CRYPTO_DEBUG`` (default: ``n``)

  Toggle display of debugging messages.

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

MVSAM CRYPTO PMD requires extra out of tree kernel modules to function properly.
Please consult ``doc/musdk_get_started.txt`` for the detailed build instructions.

.. code-block:: console

   insmod musdk_cma.ko
   insmod uio_pdrv_genirq.ko of_id="generic-uio"
   insmod crypto_safexcel.ko rings=0,0
   insmod mv_sam_uio.ko

The following parameters (all optional) are exported by the driver:

- ``max_nb_queue_pairs``: maximum number of queue pairs in the device (default: 8 - A8K, 4 - A7K/A3K).
- ``max_nb_sessions``: maximum number of sessions that can be created (default: 2048).
- ``socket_id``: socket on which to allocate the device resources on.

l2fwd-crypto example application can be used to verify MVSAM CRYPTO PMD
operation:

.. code-block:: console

   ./l2fwd-crypto --vdev=eth_mvpp2,iface=eth0 --vdev=crypto_mvsam -- \
     --cipher_op ENCRYPT --cipher_algo aes-cbc \
     --cipher_key 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f  \
     --auth_op GENERATE --auth_algo sha1-hmac \
     --auth_key 10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
