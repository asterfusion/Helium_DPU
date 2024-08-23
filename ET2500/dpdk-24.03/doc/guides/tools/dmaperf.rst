..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2023 Intel Corporation.

dpdk-test-dma-perf Application
==============================

The ``dpdk-test-dma-perf`` tool is a Data Plane Development Kit (DPDK) application
that evaluates the performance of DMA (Direct Memory Access) devices accessible in DPDK environment.
It provides a benchmark framework to assess the performance of CPU and DMA devices
under various combinations, such as varying buffer lengths, scatter-gather copy, copying in remote
memory etc. It helps in evaluating performance of DMA device as hardware acceleration vehicle in
DPDK application.

In addition, this tool supports memory-to-memory, memory-to-device and device-to-memory copy tests,
to compare the performance of CPU and DMA capabilities under various conditions with the help of a
pre-set configuration file.


Configuration
-------------

Along with EAL command-line arguments, this application supports various parameters for the
benchmarking through a configuration file. An example configuration file is provided below along
with the application to demonstrate all the parameters.

.. code-block:: ini

   [case1]
   type=DMA_MEM_COPY
   mem_size=10
   buf_size=64,8192,2,MUL
   dma_ring_size=1024
   kick_batch=32
   src_numa_node=0
   dst_numa_node=0
   cache_flush=0
   test_seconds=2
   lcore_dma=lcore10@0000:00:04.2, lcore11@0000:00:04.3
   eal_args=--in-memory --file-prefix=test

   [case2]
   type=CPU_MEM_COPY
   mem_size=10
   buf_size=64,8192,2,MUL
   src_numa_node=0
   dst_numa_node=1
   cache_flush=0
   test_seconds=2
   lcore = 3, 4
   eal_args=--in-memory --no-pci

   [case3]
   skip=1
   type=DMA_MEM_COPY
   direction=mem2dev
   vchan_dev=raddr=0x200000000,coreid=1,pfid=2,vfid=3
   dma_src_sge=4
   dma_dst_sge=1
   mem_size=10
   buf_size=64,8192,2,MUL
   dma_ring_size=1024
   kick_batch=32
   src_numa_node=0
   dst_numa_node=0
   cache_flush=0
   test_seconds=2
   lcore_dma=lcore10@0000:00:04.2, lcore11@0000:00:04.3
   eal_args=--in-memory --file-prefix=test

The configuration file is divided into multiple sections, each section represents a test case.
The four mandatory variables ``mem_size``, ``buf_size``, ``dma_ring_size``, and ``kick_batch``
can vary in each test case. The format for this is ``variable=first,last,increment,ADD|MUL``.
This means that the first value of the variable is 'first', the last value is 'last',
'increment' is the step size, and 'ADD|MUL' indicates whether the change is by addition or
multiplication.

The variables for mem2dev and dev2mem copy are ``direction``, ``vchan_dev`` and can vary in each
test case. If the direction is not configured, the default is mem2mem copy.

For scatter-gather copy test ``dma_src_sge``, ``dma_dst_sge`` must be configured.

Each case can only have one variable change,
and each change will generate a scenario, so each case can have multiple scenarios.


Configuration Parameters
~~~~~~~~~~~~~~~~~~~~~~~~

``skip``
  To skip a test-case, must be configured as ``1``

``type``
  The type of the test.
  Currently supported types are ``DMA_MEM_COPY`` and ``CPU_MEM_COPY``.

``direction``
  The direction of data transfer.
  Currently supported directions:

    * ``mem2mem`` - memory to memory copy

    * ``mem2dev`` - memory to device copy

    * ``dev2mem`` - device to memory copy

``vchan_dev``
  Comma separated bus related parameters for ``mem2dev`` and ``dev2mem`` copy.

``dma_src_sge``
  Number of source segments for scatter-gather.

``dma_dst_sge``
  Number of destination segments for scatter-gather.

``mem_size``
  The size of the memory footprint in megabytes (MB) for source and destination.

``buf_size``
  The memory size of a single operation in bytes (B).

``dma_ring_size``
  The DMA ring buffer size. Must be a power of two, and between ``64`` and ``4096``.

``kick_batch``
  The DMA operation batch size, should be greater than ``1`` normally.

``src_numa_node``
  Controls the NUMA node where the source memory is allocated.

``dst_numa_node``
  Controls the NUMA node where the destination memory is allocated.

``cache_flush``
  Determines whether the cache should be flushed.
  ``1`` indicates to flush and ``0`` to not flush.

``test_seconds``
  Controls the test time for each scenario.

``lcore_dma``
  Specifies the lcore/DMA mapping.

.. note::

   The mapping of lcore to DMA must be one-to-one and cannot be duplicated.

``lcore``
  Specifies the lcore for CPU testing.

``eal_args``
  Specifies the EAL arguments.


Running the Application
-----------------------

Typical command-line invocation to execute the application:

.. code-block:: console

   dpdk-test-dma-perf --config=./config_dma.ini --result=./res_dma.csv

Where ``config_dma.ini`` is the configuration file,
and ``res_dma.csv`` will be the generated result file.

If no result file is specified, the test results are found in a file
with the same name as the configuration file with the addition of ``_result.csv`` at the end.


Limitations
-----------

DMA copy to/from remote memory address has following limitations:

 * ``vchan_dev`` config will be same for all the configured DMA devices.
